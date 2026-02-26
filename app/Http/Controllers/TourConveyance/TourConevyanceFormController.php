<?php

namespace App\Http\Controllers\TourConveyance;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\ConveyanceDetail;
use App\Models\Employee;
use App\Models\Log;
use App\Models\TourConveyanceForm;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class TourConevyanceFormController extends Controller
{
    public function index(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized.',
            ], 401);
        }

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
        ]);

        $query = TourConveyanceForm::query();
        $search = trim((string) ($validated['search'] ?? ''));

        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('form_code', 'like', '%' . $search . '%')
                    ->orWhere('employee_name', 'like', '%' . $search . '%')
                    ->orWhere('employee_id', 'like', '%' . $search . '%')
                    ->orWhere('department', 'like', '%' . $search . '%')
                    ->orWhere('tour_location', 'like', '%' . $search . '%')
                    ->orWhere('status', 'like', '%' . $search . '%');
            });
        }

        $forms = $query->latest()->paginate(10);
        $formIds = collect($forms->items())->pluck('id')->all();

        $detailsByForm = ConveyanceDetail::whereIn('tour_conveyance_form_id', $formIds)
            ->orderBy('travel_date')
            ->get()
            ->groupBy('tour_conveyance_form_id');

        $data = collect($forms->items())->map(function (TourConveyanceForm $form) use ($detailsByForm) {
            return $this->transformForm($form, $detailsByForm->get($form->id, collect())->values()->all());
        })->values()->all();

        return response()->json([
            'status' => true,
            'message' => 'Tour conveyance forms fetched successfully.',
            'data' => $data,
            'pagination' => [
                'current_page' => $forms->currentPage(),
                'last_page' => $forms->lastPage(),
                'per_page' => $forms->perPage(),
                'total' => $forms->total(),
            ],
        ]);
    }

    public function store(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized.',
            ], 401);
        }

        $validated = $this->validateRequest($request, false);

        $form = DB::transaction(function () use ($validated) {
            $form = new TourConveyanceForm();
            $this->fillForm($form, $validated);
            $form->save();

            $this->syncConveyanceDetails($form->id, $validated['conveyance_details'] ?? []);

            return $form;
        });

        $details = ConveyanceDetail::where('tour_conveyance_form_id', $form->id)
            ->orderBy('travel_date')
            ->get()
            ->values()
            ->all();
        $this->logTourConveyanceAction($request, $admin, $form, 'create', 'created tour conveyance form for');

        return response()->json([
            'status' => true,
            'message' => 'Tour conveyance form created successfully.',
            'data' => $this->transformForm($form, $details),
        ], 201);
    }

    public function show(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized.',
            ], 401);
        }

        $form = TourConveyanceForm::find($id);
        if (!$form) {
            return response()->json([
                'status' => false,
                'message' => 'Tour conveyance form not found.',
            ], 404);
        }

        $details = ConveyanceDetail::where('tour_conveyance_form_id', $form->id)
            ->orderBy('travel_date')
            ->get()
            ->values()
            ->all();

        return response()->json([
            'status' => true,
            'message' => 'Tour conveyance form fetched successfully.',
            'data' => $this->transformForm($form, $details),
        ]);
    }

    public function update(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized.',
            ], 401);
        }

        $form = TourConveyanceForm::find($id);
        if (!$form) {
            return response()->json([
                'status' => false,
                'message' => 'Tour conveyance form not found.',
            ], 404);
        }

        $validated = $this->validateRequest($request, true, $form->id);

        DB::transaction(function () use ($form, $validated, $request) {
            $this->fillForm($form, $validated, true);
            $form->save();

            if ($request->has('conveyance_details')) {
                $this->syncConveyanceDetails($form->id, $validated['conveyance_details'] ?? []);
            }
        });

        $form->refresh();

        $details = ConveyanceDetail::where('tour_conveyance_form_id', $form->id)
            ->orderBy('travel_date')
            ->get()
            ->values()
            ->all();
        $this->logTourConveyanceAction($request, $admin, $form, 'update', 'updated tour conveyance form for');

        return response()->json([
            'status' => true,
            'message' => 'Tour conveyance form updated successfully.',
            'data' => $this->transformForm($form, $details),
        ]);
    }

    public function destroy(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized.',
            ], 401);
        }

        $form = TourConveyanceForm::find($id);
        if (!$form) {
            return response()->json([
                'status' => false,
                'message' => 'Tour conveyance form not found.',
            ], 404);
        }

        $employeeName = $form->employee_name ?: 'unknown employee';
        $resolvedEmployeeId = $this->resolveEmployeeIdFromForm($form);
        $form->delete();
        $this->logTourConveyanceDeleteAction($request, $admin, $resolvedEmployeeId, $employeeName);

        return response()->json([
            'status' => true,
            'message' => 'Tour conveyance form deleted successfully.',
        ]);
    }

    private function validateRequest(Request $request, bool $isUpdate = false, ?int $formId = null): array
    {
        $formCodeRule = $isUpdate
            ? 'sometimes|required|string|max:50|unique:tour_conveyance_forms,form_code,' . $formId
            : 'nullable|string|max:50|unique:tour_conveyance_forms,form_code';

        $required = $isUpdate ? 'sometimes|required' : 'required';

        return $request->validate([
            'form_code' => [$formCodeRule],
            'company_name' => [$required, 'string', 'max:255'],
            'company_address' => ['nullable', 'string'],
            'company_logo_path' => ['nullable', 'string', 'max:255'],
            'form_heading' => [$required, 'string', 'max:255'],
            'form_subheading' => [$required, 'string', 'max:255'],
            'form_date' => [$required, 'date'],
            'employee_name' => [$required, 'string', 'max:255'],
            'employee_id' => [$required, 'string', 'max:255'],
            'designation' => [$required, 'string', 'max:255'],
            'department' => [$required, 'string', 'max:255'],
            'reporting_manager' => [$required, 'string', 'max:255'],
            'cost_center' => [$required, 'string', 'max:255'],
            'purpose' => [$required, 'string'],
            'tour_location' => [$required, 'string', 'max:255'],
            'project_code' => ['nullable', 'string', 'max:255'],
            'tour_from' => [$required, 'date'],
            'tour_to' => [$required, 'date', 'after_or_equal:tour_from'],
            'advance_taken' => ['nullable', 'numeric', 'min:0'],
            'total_expense' => ['nullable', 'numeric', 'min:0'],
            'balance_payable' => ['nullable', 'numeric', 'min:0'],
            'balance_receivable' => ['nullable', 'numeric', 'min:0'],
            'manager_remarks' => ['nullable', 'string'],
            'status' => ['nullable', 'string', 'max:50'],
            'footer_heading' => [$required, 'string', 'max:255'],
            'footer_subheading' => [$required, 'string', 'max:255'],
            'conveyance_details' => ['sometimes', 'array'],
            'conveyance_details.*.travel_date' => ['required_with:conveyance_details', 'date'],
            'conveyance_details.*.mode' => ['required_with:conveyance_details', 'string', 'max:50'],
            'conveyance_details.*.from_location' => ['nullable', 'string', 'max:255'],
            'conveyance_details.*.to_location' => ['nullable', 'string', 'max:255'],
            'conveyance_details.*.distance' => ['nullable', 'numeric', 'min:0'],
            'conveyance_details.*.amount' => ['nullable', 'numeric', 'min:0'],
        ]);
    }

    private function fillForm(TourConveyanceForm $form, array $validated, bool $isUpdate = false): void
    {
        $fields = [
            'company_name',
            'company_address',
            'company_logo_path',
            'form_heading',
            'form_subheading',
            'form_date',
            'employee_name',
            'employee_id',
            'designation',
            'department',
            'reporting_manager',
            'cost_center',
            'purpose',
            'tour_location',
            'project_code',
            'tour_from',
            'tour_to',
            'advance_taken',
            'total_expense',
            'balance_payable',
            'balance_receivable',
            'manager_remarks',
            'status',
            'footer_heading',
            'footer_subheading',
        ];

        if (!$isUpdate) {
            $form->form_code = $validated['form_code'] ?? $this->generateFormCode();
        } elseif (array_key_exists('form_code', $validated)) {
            $form->form_code = $validated['form_code'];
        }

        foreach ($fields as $field) {
            if (!$isUpdate || array_key_exists($field, $validated)) {
                if (in_array($field, ['advance_taken', 'total_expense', 'balance_payable', 'balance_receivable'], true)) {
                    $form->{$field} = (float) ($validated[$field] ?? 0);
                } else {
                    $form->{$field} = $validated[$field] ?? null;
                }
            }
        }
    }

    private function syncConveyanceDetails(int $formId, array $details): void
    {
        ConveyanceDetail::where('tour_conveyance_form_id', $formId)->delete();

        foreach ($details as $detail) {
            $item = new ConveyanceDetail();
            $item->tour_conveyance_form_id = $formId;
            $item->travel_date = $detail['travel_date'];
            $item->mode = $detail['mode'];
            $item->from_location = $detail['from_location'] ?? null;
            $item->to_location = $detail['to_location'] ?? null;
            $item->distance = (float) ($detail['distance'] ?? 0);
            $item->amount = (float) ($detail['amount'] ?? 0);
            $item->save();
        }
    }

    private function transformForm(TourConveyanceForm $form, array $details): array
    {
        $data = $form->toArray();
        $data['conveyance_details'] = collect($details)->map(function ($detail) {
            return $detail instanceof ConveyanceDetail ? $detail->toArray() : (array) $detail;
        })->values()->all();

        return $data;
    }

    private function generateFormCode(): string
    {
        $lastId = (int) TourConveyanceForm::max('id');
        return 'BMG-TCF-' . str_pad((string) ($lastId + 1), 4, '0', STR_PAD_LEFT);
    }

    private function authenticatedAdminFromToken(Request $request): ?Admin
    {
        $token = $request->bearerToken();
        if (!$token) {
            return null;
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload) {
            return null;
        }

        if (($payload['role'] ?? null) !== 'admin') {
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

    private function logTourConveyanceAction(
        Request $request,
        Admin $admin,
        TourConveyanceForm $form,
        string $action,
        string $actionText
    ): void {
        $adminName = $admin->full_name ?: 'unknown admin';
        $employeeName = $form->employee_name ?: 'unknown employee';
        $resolvedEmployeeId = $this->resolveEmployeeIdFromForm($form);

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = $resolvedEmployeeId;
        $log->model = class_basename($form);
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

    private function logTourConveyanceDeleteAction(
        Request $request,
        Admin $admin,
        ?int $employeeId,
        string $employeeName
    ): void {
        $adminName = $admin->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = $employeeId;
        $log->model = class_basename(TourConveyanceForm::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) deleted tour conveyance form for employee(%s)',
            $adminName,
            $employeeName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function resolveEmployeeIdFromForm(TourConveyanceForm $form): ?int
    {
        $rawEmployeeId = trim((string) $form->employee_id);
        if ($rawEmployeeId === '') {
            return null;
        }

        if (ctype_digit($rawEmployeeId)) {
            $id = (int) $rawEmployeeId;
            return Employee::where('id', $id)->exists() ? $id : null;
        }

        $employee = Employee::where('emp_code', $rawEmployeeId)->first();
        return $employee?->id;
    }
}
