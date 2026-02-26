<?php

namespace App\Http\Controllers\HrMisReport;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\HrMisReport;
use App\Models\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

class HrMisReportController extends Controller
{
    public function index(Request $request)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
            'report_type' => ['nullable', 'string', 'max:255'],
            'department' => ['nullable', 'string', 'max:255'],
            'report_month' => ['nullable', 'string', 'max:50'],
            'report_year' => ['nullable', 'string', 'max:50'],
            'date_from' => ['nullable', 'date'],
            'date_to' => ['nullable', 'date', 'after_or_equal:date_from'],
        ]);

        $query = HrMisReport::query();

        if (!empty($validated['report_type'])) {
            $query->where('report_type', $validated['report_type']);
        }
        if (!empty($validated['department'])) {
            $query->where('department', $validated['department']);
        }
        if (!empty($validated['report_month'])) {
            $query->where('report_month', $validated['report_month']);
        }
        if (!empty($validated['report_year'])) {
            $query->where('report_year', $validated['report_year']);
        }
        if (!empty($validated['date_from'])) {
            $query->whereDate('report_date', '>=', $validated['date_from']);
        }
        if (!empty($validated['date_to'])) {
            $query->whereDate('report_date', '<=', $validated['date_to']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('report_type', 'like', '%' . $search . '%')
                    ->orWhere('department', 'like', '%' . $search . '%')
                    ->orWhere('center_name', 'like', '%' . $search . '%')
                    ->orWhere('report_month', 'like', '%' . $search . '%')
                    ->orWhere('report_year', 'like', '%' . $search . '%')
                    ->orWhere('remarks', 'like', '%' . $search . '%');
            });
        }

        $reports = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'HR MIS reports fetched successfully.',
            'data' => $this->transformReports($reports->items()),
            'pagination' => [
                'current_page' => $reports->currentPage(),
                'last_page' => $reports->lastPage(),
                'per_page' => $reports->perPage(),
                'total' => $reports->total(),
            ],
        ]);
    }

    public function store(Request $request)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $validated = $this->validateReportPayload($request);

        $report = new HrMisReport();
        $this->fillReportData($report, $validated);
        $report->created_by = $admin->id;
        $report->save();
        $this->logHrMisReportAction($request, $admin, $report, 'create', 'created HR MIS report');

        return response()->json([
            'status' => true,
            'message' => 'HR MIS report created successfully.',
            'data' => $this->transformReports([$report])[0],
        ], 201);
    }

    public function show(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $report = HrMisReport::find($id);
        if (!$report) {
            return response()->json([
                'status' => false,
                'message' => 'HR MIS report not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'HR MIS report fetched successfully.',
            'data' => $this->transformReports([$report])[0],
        ]);
    }

    public function update(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $report = HrMisReport::find($id);
        if (!$report) {
            return response()->json([
                'status' => false,
                'message' => 'HR MIS report not found.',
            ], 404);
        }

        $validated = $this->validateReportPayload($request, true);
        $this->fillReportData($report, $validated);
        $report->save();
        $this->logHrMisReportAction($request, $admin, $report, 'update', 'updated HR MIS report');

        return response()->json([
            'status' => true,
            'message' => 'HR MIS report updated successfully.',
            'data' => $this->transformReports([$report])[0],
        ]);
    }

    public function destroy(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminOrSubAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin or sub admin token is required.',
            ], 401);
        }

        $report = HrMisReport::find($id);
        if (!$report) {
            return response()->json([
                'status' => false,
                'message' => 'HR MIS report not found.',
            ], 404);
        }

        $reportType = $report->report_type ?: 'unknown type';
        $report->delete();
        $this->logHrMisReportDeleteAction($request, $admin, $reportType);

        return response()->json([
            'status' => true,
            'message' => 'HR MIS report deleted successfully.',
        ]);
    }

    private function transformReports(array $reports): array
    {
        $creatorIds = collect($reports)->pluck('created_by')->filter()->unique()->values();
        $creators = Admin::whereIn('id', $creatorIds)->get()->keyBy('id');

        return array_map(function (HrMisReport $report) use ($creators) {
            $creator = $creators->get($report->created_by);
            $creatorData = null;

            if ($creator) {
                $creatorData = $creator->toArray();
                unset($creatorData['password']);
                $creatorData['profile_photo'] = $creator->profile_photo ? url(Storage::url($creator->profile_photo)) : null;
            }

            $data = $report->toArray();
            $data['created_by_admin'] = $creatorData;

            return $data;
        }, $reports);
    }

    private function validateReportPayload(Request $request, bool $isUpdate = false): array
    {
        $required = $isUpdate ? 'sometimes' : 'required';

        return $request->validate([
            'report_type' => [$required, 'string', 'max:255'],
            'department' => ['nullable', 'string', 'max:255'],
            'report_date' => ['nullable', 'date'],
            'report_month' => ['nullable', 'string', 'max:50'],
            'report_year' => ['nullable', 'string', 'max:50'],
            'center_name' => ['nullable', 'string', 'max:255'],
            'week_start_date' => ['nullable', 'date'],
            'week_end_date' => ['nullable', 'date', 'after_or_equal:week_start_date'],
            'total_employees' => ['nullable', 'integer', 'min:0'],
            'new_hires' => ['nullable', 'integer', 'min:0'],
            'terminations' => ['nullable', 'integer', 'min:0'],
            'resignations' => ['nullable', 'integer', 'min:0'],
            'strength' => ['nullable', 'integer', 'min:0'],
            'total_present' => ['nullable', 'integer', 'min:0'],
            'total_absent' => ['nullable', 'integer', 'min:0'],
            'total_leave' => ['nullable', 'integer', 'min:0'],
            'total_halfday' => ['nullable', 'integer', 'min:0'],
            'total_holiday' => ['nullable', 'integer', 'min:0'],
            'requirement_raised' => ['nullable', 'integer', 'min:0'],
            'position_pending' => ['nullable', 'integer', 'min:0'],
            'position_closed' => ['nullable', 'integer', 'min:0'],
            'interviews_conducted' => ['nullable', 'integer', 'min:0'],
            'selected' => ['nullable', 'integer', 'min:0'],
            'rejected' => ['nullable', 'integer', 'min:0'],
            'process' => ['nullable', 'in:yes,no'],
            'salary_disbursement_date' => ['nullable', 'date'],
            'deduction' => ['nullable', 'string', 'max:255'],
            'pending_compliance' => ['nullable', 'string'],
            'grievance_received' => ['nullable', 'integer', 'min:0'],
            'grievance_resolved' => ['nullable', 'integer', 'min:0'],
            'warning_notice' => ['nullable', 'integer', 'min:0'],
            'appreciation' => ['nullable', 'integer', 'min:0'],
            'training_conducted' => ['nullable', 'integer', 'min:0'],
            'employee_attend' => ['nullable', 'integer', 'min:0'],
            'training_feedback' => ['nullable', 'string', 'max:255'],
            'birthday_celebration' => ['nullable', 'string', 'max:255'],
            'engagement_activities' => ['nullable', 'string', 'max:255'],
            'hr_initiatives' => ['nullable', 'string', 'max:255'],
            'special_events' => ['nullable', 'string', 'max:255'],
            'notes' => ['nullable', 'string'],
            'remarks' => ['nullable', 'string', 'max:255'],
        ]);
    }

    private function fillReportData(HrMisReport $report, array $validated): void
    {
        foreach ($validated as $field => $value) {
            $report->{$field} = $value;
        }

        if (!array_key_exists('process', $validated) && !$report->exists) {
            $report->process = 'no';
        }
    }

    private function authenticatedAdminOrSubAdminFromToken(Request $request): ?Admin
    {
        $token = $request->bearerToken();
        if (!$token) {
            return null;
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload) {
            return null;
        }

        $role = strtolower((string) ($payload['role'] ?? ''));
        if (!in_array($role, ['admin', 'sub_admin', 'subadmin'], true)) {
            return null;
        }

        $adminId = (int) ($payload['sub'] ?? 0);
        if ($adminId <= 0) {
            return null;
        }

        return Admin::find($adminId);
    }

    private function decodeJwtToken(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
        $signature = $this->base64UrlDecode($encodedSignature);
        if ($signature === false) {
            return null;
        }

        $expectedSignature = hash_hmac('sha256', $encodedHeader . '.' . $encodedPayload, $this->jwtSecret(), true);
        if (!hash_equals($expectedSignature, $signature)) {
            return null;
        }

        $payloadJson = $this->base64UrlDecode($encodedPayload);
        if ($payloadJson === false) {
            return null;
        }

        $payload = json_decode($payloadJson, true);
        if (!is_array($payload)) {
            return null;
        }

        $blacklistKey = 'admin_jwt_blacklist:' . hash('sha256', $token);
        if (Cache::has($blacklistKey)) {
            return null;
        }

        return $payload;
    }

    private function jwtSecret(): string
    {
        $secret = env('JWT_SECRET');
        if (!empty($secret)) {
            return $secret;
        }

        $appKey = (string) config('app.key', '');
        if (str_starts_with($appKey, 'base64:')) {
            $decoded = base64_decode(substr($appKey, 7), true);
            if ($decoded !== false) {
                return $decoded;
            }
        }

        return $appKey;
    }

    private function base64UrlDecode(string $value): string|false
    {
        $remainder = strlen($value) % 4;
        if ($remainder) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($value, '-_', '+/'), true);
    }

    private function logHrMisReportAction(
        Request $request,
        Admin $admin,
        HrMisReport $report,
        string $action,
        string $actionText
    ): void {
        $adminName = $admin->full_name ?: 'unknown admin';
        $reportType = $report->report_type ?: 'unknown type';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = null;
        $log->model = class_basename($report);
        $log->action = $action;
        $log->description = sprintf(
            'admin(%s) %s (%s)',
            $adminName,
            $actionText,
            $reportType
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logHrMisReportDeleteAction(Request $request, Admin $admin, string $reportType): void
    {
        $adminName = $admin->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = null;
        $log->model = class_basename(HrMisReport::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) deleted HR MIS report (%s)',
            $adminName,
            $reportType
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
