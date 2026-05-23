<?php

namespace App\Http\Controllers\MemberAssign;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Employee;
use App\Models\Log;
use App\Models\MemberAssign;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class MemberAssignController extends Controller
{
    public function index(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
            'tl_id' => ['nullable', 'integer', 'exists:employees,id'],
            'employee_id' => ['nullable', 'integer', 'exists:employees,id'],
            'assigned_by' => ['nullable', 'integer', 'exists:admins,id'],
        ]);

        $query = MemberAssign::with(['tl', 'employee', 'assignedBy']);

        if (!empty($validated['tl_id'])) {
            $query->where('tl_id', (int) $validated['tl_id']);
        }

        if (!empty($validated['employee_id'])) {
            $query->where('employee_id', (int) $validated['employee_id']);
        }

        if (!empty($validated['assigned_by'])) {
            $query->where('assigned_by', (int) $validated['assigned_by']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->whereHas('tl', function ($employeeQuery) use ($search) {
                    $employeeQuery->where('emp_name', 'like', '%' . $search . '%')
                        ->orWhere('emp_code', 'like', '%' . $search . '%')
                        ->orWhere('emp_email', 'like', '%' . $search . '%');
                })->orWhereHas('employee', function ($employeeQuery) use ($search) {
                    $employeeQuery->where('emp_name', 'like', '%' . $search . '%')
                        ->orWhere('emp_code', 'like', '%' . $search . '%')
                        ->orWhere('emp_email', 'like', '%' . $search . '%');
                })->orWhereHas('assignedBy', function ($adminQuery) use ($search) {
                    $adminQuery->where('full_name', 'like', '%' . $search . '%')
                        ->orWhere('email', 'like', '%' . $search . '%');
                });
            });
        }

        $assignments = $query->latest('id')->paginate(10);
        $data = collect($assignments->items())
            ->map(fn (MemberAssign $assignment) => $this->transformAssignment($assignment))
            ->values()
            ->all();

        return response()->json([
            'status' => true,
            'message' => 'Team member assignments fetched successfully.',
            'data' => $data,
            'pagination' => [
                'current_page' => $assignments->currentPage(),
                'last_page' => $assignments->lastPage(),
                'per_page' => $assignments->perPage(),
                'total' => $assignments->total(),
            ],
        ]);
    }

    public function store(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'tl_id' => ['required', 'integer', 'exists:employees,id'],
            'employee_id' => ['nullable', 'integer', 'exists:employees,id'],
            'employee_ids' => ['nullable', 'array', 'min:1'],
            'employee_ids.*' => ['integer', 'distinct', 'exists:employees,id'],
        ]);

        $employeeIds = $this->normalizeEmployeeIds($validated);
        if ($employeeIds === []) {
            return response()->json([
                'status' => false,
                'message' => 'Please provide employee_id or employee_ids.',
            ], 422);
        }

        $tl = $this->resolveTeamLead($validated['tl_id']);
        if (!$tl) {
            return response()->json([
                'status' => false,
                'message' => 'Selected TL is invalid. Please choose an employee with TL role.',
            ], 422);
        }

        $createdAssignments = [];
        $skippedAssignments = [];

        foreach ($employeeIds as $employeeId) {
            if ((int) $tl->id === (int) $employeeId) {
                $skippedAssignments[] = [
                    'employee_id' => (int) $employeeId,
                    'message' => 'TL and employee cannot be the same person.',
                ];
                continue;
            }

            $employee = $this->resolveAssignableEmployee($employeeId);
            if (!$employee) {
                $skippedAssignments[] = [
                    'employee_id' => (int) $employeeId,
                    'message' => 'Selected employee is invalid. TL cannot be assigned as a team member.',
                ];
                continue;
            }

            $existingAssignment = MemberAssign::where('employee_id', $employee->id)->first();
            if ($existingAssignment) {
                $skippedAssignments[] = [
                    'employee_id' => (int) $employee->id,
                    'message' => 'This employee is already assigned to a TL team.',
                ];
                continue;
            }

            $assignment = MemberAssign::create([
                'tl_id' => $tl->id,
                'employee_id' => $employee->id,
                'assigned_by' => $admin->id,
            ]);

            $assignment->load(['tl', 'employee', 'assignedBy']);
            $this->logMemberAssignAction($request, $admin, $assignment, 'create', 'assigned employee');
            $createdAssignments[] = $this->transformAssignment($assignment);
        }

        if ($createdAssignments === []) {
            return response()->json([
                'status' => false,
                'message' => 'No employees were assigned to this TL.',
                'skipped' => $skippedAssignments,
            ], 422);
        }

        return response()->json([
            'status' => true,
            'message' => count($createdAssignments) === 1
                ? 'Employee assigned to TL successfully.'
                : 'Employees assigned to TL successfully.',
            'data' => $createdAssignments,
            'skipped' => $skippedAssignments,
        ], 201);
    }

    public function show(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $assignment = MemberAssign::with(['tl', 'employee', 'assignedBy'])->find($id);
        if (!$assignment) {
            return response()->json([
                'status' => false,
                'message' => 'Team member assignment not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Team member assignment fetched successfully.',
            'data' => $this->transformAssignment($assignment),
        ]);
    }

    public function update(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $assignment = MemberAssign::find($id);
        if (!$assignment) {
            return response()->json([
                'status' => false,
                'message' => 'Team member assignment not found.',
            ], 404);
        }

        $validated = $request->validate([
            'tl_id' => ['sometimes', 'required', 'integer', 'exists:employees,id'],
            'employee_id' => ['sometimes', 'required', 'integer', 'exists:employees,id'],
        ]);

        $tlId = (int) ($validated['tl_id'] ?? $assignment->tl_id);
        $employeeId = (int) ($validated['employee_id'] ?? $assignment->employee_id);

        if ($tlId === $employeeId) {
            return response()->json([
                'status' => false,
                'message' => 'TL and employee cannot be the same person.',
            ], 422);
        }

        $tl = $this->resolveTeamLead($tlId);
        if (!$tl) {
            return response()->json([
                'status' => false,
                'message' => 'Selected TL is invalid. Please choose an employee with TL role.',
            ], 422);
        }

        $employee = $this->resolveAssignableEmployee($employeeId);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Selected employee is invalid. TL cannot be assigned as a team member.',
            ], 422);
        }

        $duplicate = MemberAssign::where('employee_id', $employeeId)
            ->where('id', '!=', $assignment->id)
            ->exists();

        if ($duplicate) {
            return response()->json([
                'status' => false,
                'message' => 'This employee is already assigned to another TL team.',
            ], 422);
        }

        $assignment->tl_id = $tl->id;
        $assignment->employee_id = $employee->id;
        $assignment->assigned_by = $admin->id;
        $assignment->save();

        $assignment->load(['tl', 'employee', 'assignedBy']);
        $this->logMemberAssignAction($request, $admin, $assignment, 'update', 'updated team assignment of employee');

        return response()->json([
            'status' => true,
            'message' => 'Team member assignment updated successfully.',
            'data' => $this->transformAssignment($assignment),
        ]);
    }

    public function destroy(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $assignment = MemberAssign::with(['tl', 'employee'])->find($id);
        if (!$assignment) {
            return response()->json([
                'status' => false,
                'message' => 'Team member assignment not found.',
            ], 404);
        }

        $employeeId = $assignment->employee_id;
        $employeeName = $assignment->employee?->emp_name ?: $this->resolveEmployeeName($employeeId);
        $tlName = $assignment->tl?->emp_name ?: $this->resolveEmployeeName($assignment->tl_id);

        $assignment->delete();
        $this->logMemberAssignDeleteAction($request, $admin, $employeeId, $employeeName, $tlName);

        return response()->json([
            'status' => true,
            'message' => 'Team member assignment deleted successfully.',
        ]);
    }

    private function transformAssignment(MemberAssign $assignment): array
    {
        return [
            'id' => (int) $assignment->id,
            'tl_id' => (int) $assignment->tl_id,
            'employee_id' => (int) $assignment->employee_id,
            'assigned_by' => $assignment->assigned_by ? (int) $assignment->assigned_by : null,
            'created_at' => $assignment->created_at,
            'updated_at' => $assignment->updated_at,
            'tl' => $this->transformEmployeeSummary($assignment->tl),
            'employee' => $this->transformEmployeeSummary($assignment->employee),
            'assigned_by_admin' => $assignment->assignedBy ? [
                'id' => (int) $assignment->assignedBy->id,
                'full_name' => $assignment->assignedBy->full_name,
                'email' => $assignment->assignedBy->email,
                'role' => $assignment->assignedBy->role,
            ] : null,
        ];
    }

    private function transformEmployeeSummary(?Employee $employee): ?array
    {
        if (!$employee) {
            return null;
        }

        return [
            'id' => (int) $employee->id,
            'emp_code' => $employee->emp_code,
            'emp_name' => $employee->emp_name,
            'emp_email' => $employee->emp_email,
            'emp_phone' => $employee->emp_phone,
            'role' => $employee->role,
            'status' => $employee->status,
            'profile_photo' => $employee->profile_photo ? url('public/storage/' . $employee->profile_photo) : null,
        ];
    }

    private function normalizeEmployeeIds(array $validated): array
    {
        return collect([
            $validated['employee_id'] ?? null,
            ...($validated['employee_ids'] ?? []),
        ])
            ->filter(fn ($employeeId) => $employeeId !== null && $employeeId !== '')
            ->map(fn ($employeeId) => (int) $employeeId)
            ->unique()
            ->values()
            ->all();
    }

    private function resolveTeamLead(int $employeeId): ?Employee
    {
        $employee = Employee::find($employeeId);

        if (!$employee || !$this->isTeamLeadRole($employee->role)) {
            return null;
        }

        return $employee;
    }

    private function resolveAssignableEmployee(int $employeeId): ?Employee
    {
        $employee = Employee::find($employeeId);

        if (!$employee || $this->isTeamLeadRole($employee->role)) {
            return null;
        }

        return $employee;
    }

    private function isTeamLeadRole(?string $role): bool
    {
        $normalizedRole = str_replace([' ', '-'], '_', strtolower(trim((string) $role)));

        return in_array($normalizedRole, ['tl', 'team_lead'], true);
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

        $role = strtolower((string) ($payload['role'] ?? ''));
        if (!in_array($role, ['admin', 'subadmin', 'sub_admin'], true)) {
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

    private function logMemberAssignAction(
        Request $request,
        Admin $admin,
        MemberAssign $assignment,
        string $action,
        string $actionText
    ): void {
        if (strtolower((string) $admin->role) === 'admin') {
            return;
        }

        $adminName = $admin->full_name ?: 'unknown admin';
        $employeeName = $assignment->employee?->emp_name ?: $this->resolveEmployeeName($assignment->employee_id);
        $tlName = $assignment->tl?->emp_name ?: $this->resolveEmployeeName($assignment->tl_id);

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = $assignment->employee_id;
        $log->model = class_basename($assignment);
        $log->action = $action;
        $log->description = sprintf(
            'admin(%s) %s employee(%s) to tl(%s)',
            $adminName,
            $actionText,
            $employeeName,
            $tlName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logMemberAssignDeleteAction(
        Request $request,
        Admin $admin,
        ?int $employeeId,
        string $employeeName,
        string $tlName
    ): void {
        if (strtolower((string) $admin->role) === 'admin') {
            return;
        }

        $adminName = $admin->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = $employeeId;
        $log->model = class_basename(MemberAssign::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) removed employee(%s) from tl(%s) team',
            $adminName,
            $employeeName,
            $tlName
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
}
