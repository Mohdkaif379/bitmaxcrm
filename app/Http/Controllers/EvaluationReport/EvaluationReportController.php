<?php

namespace App\Http\Controllers\EvaluationReport;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Employee;
use App\Models\EvaluationReport;
use App\Models\Log;
use App\Models\Notification;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;

class EvaluationReportController extends Controller
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
            'employee_id' => ['nullable', 'integer', 'exists:employees,id'],
            'search' => ['nullable', 'string', 'max:255'],
            'period_from' => ['nullable', 'date'],
            'period_to' => ['nullable', 'date', 'after_or_equal:period_from'],
            'evaluation_date' => ['nullable', 'date'],
            'performance_grade' => ['nullable', 'string', 'max:100'],
        ]);

        $query = EvaluationReport::query();

        if (!empty($validated['employee_id'])) {
            $query->where('employee_id', (int) $validated['employee_id']);
        }

        if (!empty($validated['period_from'])) {
            $query->whereDate('period_from', '>=', $validated['period_from']);
        }

        if (!empty($validated['period_to'])) {
            $query->whereDate('period_to', '<=', $validated['period_to']);
        }

        if (!empty($validated['evaluation_date'])) {
            $query->whereDate('evaluation_date', $validated['evaluation_date']);
        }

        if (!empty($validated['performance_grade'])) {
            $query->where('performance_grade', $validated['performance_grade']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $employeeIds = Employee::query()
                ->where('emp_name', 'like', '%' . $search . '%')
                ->orWhere('emp_email', 'like', '%' . $search . '%')
                ->orWhere('emp_code', 'like', '%' . $search . '%')
                ->pluck('id');

            $query->where(function ($builder) use ($search, $employeeIds) {
                $builder->whereIn('employee_id', $employeeIds)
                    ->orWhere('performance_grade', 'like', '%' . $search . '%')
                    ->orWhere('manager_comments', 'like', '%' . $search . '%')
                    ->orWhere('hr_comments', 'like', '%' . $search . '%')
                    ->orWhere('final_feedback', 'like', '%' . $search . '%');
            });
        }

        $reports = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Evaluation reports fetched successfully.',
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

        $validated = $this->validatePayload($request);

        $report = new EvaluationReport();
        $this->fillReport($report, $validated);
        if ($this->evaluationReportsHasCreatedByColumn()) {
            $report->created_by = $admin->id;
        }
        $report->save();

        $this->logEvaluationReportAction($request, $admin, $report, 'create', 'created evaluation report for');
        $this->createEvaluationReportNotification($admin, $report, 'create');

        return response()->json([
            'status' => true,
            'message' => 'Evaluation report created successfully.',
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

        $report = EvaluationReport::find($id);
        if (!$report) {
            return response()->json([
                'status' => false,
                'message' => 'Evaluation report not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Evaluation report fetched successfully.',
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

        $report = EvaluationReport::find($id);
        if (!$report) {
            return response()->json([
                'status' => false,
                'message' => 'Evaluation report not found.',
            ], 404);
        }

        $validated = $this->validatePayload($request, true);
        $this->fillReport($report, $validated, true);
        $report->save();

        $this->logEvaluationReportAction($request, $admin, $report, 'update', 'updated evaluation report for');
        $this->createEvaluationReportNotification($admin, $report, 'update');

        return response()->json([
            'status' => true,
            'message' => 'Evaluation report updated successfully.',
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

        $report = EvaluationReport::find($id);
        if (!$report) {
            return response()->json([
                'status' => false,
                'message' => 'Evaluation report not found.',
            ], 404);
        }

        $employeeId = $report->employee_id;
        $employeeName = $this->resolveEmployeeName($employeeId);
        $report->delete();

        $this->logEvaluationReportDeleteAction($request, $admin, $employeeId, $employeeName);
        $this->createEvaluationReportDeleteNotification($admin, $employeeId, $employeeName);

        return response()->json([
            'status' => true,
            'message' => 'Evaluation report deleted successfully.',
        ]);
    }

    private function validatePayload(Request $request, bool $isUpdate = false): array
    {
        $requiredRules = $isUpdate ? ['sometimes', 'required'] : ['required'];

        return $request->validate([
            'employee_id' => array_merge($requiredRules, ['integer', 'exists:employees,id']),
            'period_to' => array_merge($requiredRules, ['date']),
            'period_from' => array_merge($requiredRules, ['date', 'before_or_equal:period_to']),
            'evaluation_date' => array_merge($requiredRules, ['date']),
            'delivery_updates' => array_merge($requiredRules, ['string', 'max:255']),
            'quality_standards' => array_merge($requiredRules, ['string', 'max:255']),
            'application_performance' => array_merge($requiredRules, ['string', 'max:255']),
            'completion_accuracy' => array_merge($requiredRules, ['string', 'max:255']),
            'innovation_problems' => array_merge($requiredRules, ['string', 'max:255']),
            'task_efficiency' => array_merge($requiredRules, ['integer', 'min:0']),
            'ui_ux_completion' => array_merge($requiredRules, ['integer', 'min:0']),
            'debug_testing' => array_merge($requiredRules, ['integer', 'min:0']),
            'version_control' => array_merge($requiredRules, ['integer', 'min:0']),
            'document_quality' => array_merge($requiredRules, ['integer', 'min:0']),
            'manager_comments' => array_merge($requiredRules, ['string']),
            'collaboration_teamwork' => array_merge($requiredRules, ['string', 'max:255']),
            'communicate_reports' => array_merge($requiredRules, ['string', 'max:255']),
            'attendence_punctuality' => array_merge($requiredRules, ['string', 'max:255']),
            'professionalism' => array_merge($requiredRules, ['integer', 'min:0']),
            'team_collaboration' => array_merge($requiredRules, ['integer', 'min:0']),
            'learning_adaptability' => array_merge($requiredRules, ['integer', 'min:0']),
            'initiate_ownership' => array_merge($requiredRules, ['integer', 'min:0']),
            'team_management' => array_merge($requiredRules, ['integer', 'min:0']),
            'hr_comments' => array_merge($requiredRules, ['string']),
            'skills' => array_merge($requiredRules, ['integer', 'min:0']),
            'task_delivery' => array_merge($requiredRules, ['integer', 'min:0']),
            'quality_work' => array_merge($requiredRules, ['integer', 'min:0']),
            'communication' => array_merge($requiredRules, ['integer', 'min:0']),
            'behaviour_teamwork' => array_merge($requiredRules, ['integer', 'min:0']),
            'performance_grade' => array_merge($requiredRules, ['string', 'max:100']),
            'final_feedback' => array_merge($requiredRules, ['string']),
        ]);
    }

    private function fillReport(EvaluationReport $report, array $validated, bool $isUpdate = false): void
    {
        $fields = [
            'employee_id',
            'period_to',
            'period_from',
            'evaluation_date',
            'delivery_updates',
            'quality_standards',
            'application_performance',
            'completion_accuracy',
            'innovation_problems',
            'task_efficiency',
            'ui_ux_completion',
            'debug_testing',
            'version_control',
            'document_quality',
            'manager_comments',
            'collaboration_teamwork',
            'communicate_reports',
            'attendence_punctuality',
            'professionalism',
            'team_collaboration',
            'learning_adaptability',
            'initiate_ownership',
            'team_management',
            'hr_comments',
            'skills',
            'task_delivery',
            'quality_work',
            'communication',
            'behaviour_teamwork',
            'performance_grade',
            'final_feedback',
        ];

        foreach ($fields as $field) {
            if (!$isUpdate || array_key_exists($field, $validated)) {
                $report->{$field} = $validated[$field] ?? null;
            }
        }
    }

    private function transformReports(array $reports): array
    {
        $employeeIds = collect($reports)->pluck('employee_id')->filter()->unique()->values();
        $employees = Employee::whereIn('id', $employeeIds)->get()->keyBy('id');

        return array_map(function (EvaluationReport $report) use ($employees) {
            $data = $report->toArray();
            $employee = $employees->get($report->employee_id);

            $data['employee'] = $employee ? [
                'id' => $employee->id,
                'emp_code' => $employee->emp_code,
                'emp_name' => $employee->emp_name,
                'emp_email' => $employee->emp_email,
            ] : null;

            return $data;
        }, $reports);
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

    private function logEvaluationReportAction(
        Request $request,
        Admin $admin,
        EvaluationReport $report,
        string $action,
        string $actionText
    ): void {
        $adminName = $admin->full_name ?: 'unknown admin';
        $employeeName = $this->resolveEmployeeName($report->employee_id);

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = $report->employee_id;
        $log->model = class_basename($report);
        $log->action = $action;
        $log->description = sprintf(
            'admin(%s) %s employee(%s)',
            $adminName,
            $actionText,
            $employeeName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logEvaluationReportDeleteAction(Request $request, Admin $admin, ?int $employeeId, string $employeeName): void
    {
        $adminName = $admin->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = $employeeId;
        $log->model = class_basename(EvaluationReport::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) deleted evaluation report for employee(%s)',
            $adminName,
            $employeeName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function resolveEmployeeName(?int $employeeId): string
    {
        if (!$employeeId) {
            return 'unknown employee';
        }

        $employee = Employee::find($employeeId);
        return $employee?->emp_name ?: 'unknown employee';
    }

    private function evaluationReportsHasCreatedByColumn(): bool
    {
        static $hasCreatedBy = null;

        if ($hasCreatedBy === null) {
            $hasCreatedBy = Schema::hasColumn('evaluation_reports', 'created_by');
        }

        return $hasCreatedBy;
    }

    private function createEvaluationReportNotification(Admin $admin, EvaluationReport $report, string $action): void
    {
        $adminName = $admin->full_name ?: 'unknown admin';
        $employeeName = $this->resolveEmployeeName($report->employee_id);

        $title = $action === 'update'
            ? 'Evaluation report updated'
            : 'Evaluation report created';
        $messageAction = $action === 'update' ? 'updated' : 'created';

        $notification = new Notification();
        $notification->admin_id = $admin->id;
        $notification->employee_id = $report->employee_id;
        $notification->title = $title;
        $notification->message = sprintf(
            'admin(%s) %s evaluation report of employee(%s)',
            $adminName,
            $messageAction,
            $employeeName
        );
        $notification->is_read = false;
        $notification->save();
    }

    private function createEvaluationReportDeleteNotification(Admin $admin, ?int $employeeId, string $employeeName): void
    {
        $adminName = $admin->full_name ?: 'unknown admin';

        $notification = new Notification();
        $notification->admin_id = $admin->id;
        $notification->employee_id = $employeeId;
        $notification->title = 'Evaluation report deleted';
        $notification->message = sprintf(
            'admin(%s) deleted evaluation report of employee(%s)',
            $adminName,
            $employeeName
        );
        $notification->is_read = false;
        $notification->save();
    }
}
