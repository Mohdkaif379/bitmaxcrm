<?php

namespace App\Http\Controllers\TaskAssign;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Employee;
use App\Models\EmployeeTask;
use App\Models\Log;
use App\Models\Task;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class TaskAssignController extends Controller
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
            'employee_id' => ['nullable', 'integer', 'exists:employees,id'],
            'task_id' => ['nullable', 'integer', 'exists:tasks,id'],
        ]);

        $query = EmployeeTask::with(['employee', 'task']);

        if (!empty($validated['employee_id'])) {
            $query->where('employee_id', $validated['employee_id']);
        }

        if (!empty($validated['task_id'])) {
            $query->where('task_id', $validated['task_id']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->whereHas('employee', function ($employeeQuery) use ($search) {
                    $employeeQuery->where('emp_name', 'like', '%' . $search . '%')
                        ->orWhere('emp_code', 'like', '%' . $search . '%');
                })->orWhereHas('task', function ($taskQuery) use ($search) {
                    $taskQuery->where('task_name', 'like', '%' . $search . '%');
                });
            });
        }

        $assignments = $query->latest('id')->paginate(10);
        $data = collect($assignments->items())
            ->map(fn (EmployeeTask $assignment) => $this->transformAssignment($assignment))
            ->values()
            ->all();

        return response()->json([
            'status' => true,
            'message' => 'Task assignments fetched successfully.',
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
                'message' => 'Unauthorized.',
            ], 401);
        }

        $validated = $request->validate([
            'employee_id' => ['required', 'integer', 'exists:employees,id'],
            'task_id' => ['required', 'integer', 'exists:tasks,id'],
            'assigned_at' => ['nullable', 'date'],
        ]);

        $duplicate = EmployeeTask::where('employee_id', $validated['employee_id'])
            ->where('task_id', $validated['task_id'])
            ->exists();

        if ($duplicate) {
            return response()->json([
                'status' => false,
                'message' => 'This task is already assigned to this employee.',
            ], 422);
        }

        $assignment = new EmployeeTask();
        $assignment->employee_id = $validated['employee_id'];
        $assignment->task_id = $validated['task_id'];

        if (!empty($validated['assigned_at'])) {
            $assignment->created_at = $validated['assigned_at'];
            $assignment->updated_at = $validated['assigned_at'];
        }

        $assignment->save();
        $assignment->load(['employee', 'task']);
        $this->logTaskAssignAction($request, $admin, $assignment, 'create', 'assigned task');

        return response()->json([
            'status' => true,
            'message' => 'Task assigned successfully.',
            'data' => $this->transformAssignment($assignment),
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

        $assignment = EmployeeTask::with(['employee', 'task'])->find($id);

        if (!$assignment) {
            return response()->json([
                'status' => false,
                'message' => 'Task assignment not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Task assignment fetched successfully.',
            'data' => $this->transformAssignment($assignment),
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

        $assignment = EmployeeTask::find($id);
        if (!$assignment) {
            return response()->json([
                'status' => false,
                'message' => 'Task assignment not found.',
            ], 404);
        }

        $validated = $request->validate([
            'employee_id' => ['sometimes', 'required', 'integer', 'exists:employees,id'],
            'task_id' => ['sometimes', 'required', 'integer', 'exists:tasks,id'],
        ]);

        $employeeId = $validated['employee_id'] ?? $assignment->employee_id;
        $taskId = $validated['task_id'] ?? $assignment->task_id;

        $duplicate = EmployeeTask::where('employee_id', $employeeId)
            ->where('task_id', $taskId)
            ->where('id', '!=', $assignment->id)
            ->exists();

        if ($duplicate) {
            return response()->json([
                'status' => false,
                'message' => 'This task is already assigned to this employee.',
            ], 422);
        }

        $assignment->employee_id = $employeeId;
        $assignment->task_id = $taskId;
        $assignment->save();
        $assignment->load(['employee', 'task']);
        $this->logTaskAssignAction($request, $admin, $assignment, 'update', 'updated task assignment');

        return response()->json([
            'status' => true,
            'message' => 'Task assignment updated successfully.',
            'data' => $this->transformAssignment($assignment),
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

        $assignment = EmployeeTask::find($id);
        if (!$assignment) {
            return response()->json([
                'status' => false,
                'message' => 'Task assignment not found.',
            ], 404);
        }

        $employeeId = $assignment->employee_id;
        $employeeName = $this->resolveEmployeeName($employeeId);
        $taskName = $this->resolveTaskName($assignment->task_id);
        $assignment->delete();
        $this->logTaskAssignDeleteAction($request, $admin, $employeeId, $employeeName, $taskName);

        return response()->json([
            'status' => true,
            'message' => 'Task assignment deleted successfully.',
        ]);
    }

    private function transformAssignment(EmployeeTask $assignment): array
    {
        $employee = $assignment->employee ? $assignment->employee->toArray() : null;
        if (is_array($employee)) {
            unset($employee['password']);
        }

        return [
            'id' => (int) $assignment->id,
            'employee_id' => (int) $assignment->employee_id,
            'task_id' => (int) $assignment->task_id,
            'created_at' => $assignment->created_at,
            'updated_at' => $assignment->updated_at,
            'employee' => $employee,
            'task' => $assignment->task ? $assignment->task->toArray() : null,
        ];
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

    private function logTaskAssignAction(
        Request $request,
        Admin $admin,
        EmployeeTask $assignment,
        string $action,
        string $actionText
    ): void {
        $adminName = $admin->full_name ?: 'unknown admin';
        $employeeName = $this->resolveEmployeeName($assignment->employee_id);
        $taskName = $this->resolveTaskName($assignment->task_id);

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = $assignment->employee_id;
        $log->model = class_basename($assignment);
        $log->action = $action;
        $log->description = sprintf(
            'admin(%s) %s (%s) to employee(%s)',
            $adminName,
            $actionText,
            $taskName,
            $employeeName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logTaskAssignDeleteAction(
        Request $request,
        Admin $admin,
        ?int $employeeId,
        string $employeeName,
        string $taskName
    ): void {
        $adminName = $admin->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = $employeeId;
        $log->model = class_basename(EmployeeTask::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) deleted task assignment (%s) for employee(%s)',
            $adminName,
            $taskName,
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

    private function resolveTaskName(?int $taskId): string
    {
        if (!$taskId) {
            return 'unknown task';
        }

        $task = Task::find($taskId);
        return $task?->task_name ?: 'unknown task';
    }
}
