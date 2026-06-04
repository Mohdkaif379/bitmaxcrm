<?php

namespace App\Http\Controllers\MyTaskManagement;

use App\Http\Controllers\Controller;
use App\Models\Employee;
use App\Models\TaskManagement;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Validation\Rule;

class MyTaskManagementController extends Controller
{
    public function index(Request $request)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
            'project_id' => ['nullable', 'integer', 'exists:projects,id'],
            'priority' => ['nullable', Rule::in(['low', 'medium', 'high'])],
            'type' => ['nullable', 'string', 'max:255'],
        ]);

        $query = TaskManagement::with(['project.tl', 'assignedEmployee'])
            ->assignedToEmployee((int) $employee->id);

        if (!empty($validated['project_id'])) {
            $query->where('project_id', (int) $validated['project_id']);
        }

        if (!empty($validated['priority'])) {
            $query->where('priority', $validated['priority']);
        }

        if (!empty($validated['type'])) {
            $query->where('type', $validated['type']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('task_name', 'like', '%' . $search . '%')
                    ->orWhere('type', 'like', '%' . $search . '%')
                    ->orWhereHas('project', function ($projectQuery) use ($search) {
                        $projectQuery->where('title', 'like', '%' . $search . '%')
                            ->orWhere('project_code', 'like', '%' . $search . '%');
                    });
            });
        }

        $tasks = $query->latest('id')->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'My task management records fetched successfully.',
            'employee' => $this->transformEmployee($employee),
            'data' => collect($tasks->items())
                ->map(fn (TaskManagement $task) => $this->transformTask($task))
                ->values()
                ->all(),
            'pagination' => [
                'current_page' => $tasks->currentPage(),
                'last_page' => $tasks->lastPage(),
                'per_page' => $tasks->perPage(),
                'total' => $tasks->total(),
            ],
        ]);
    }

    public function show(Request $request, int $id)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $task = TaskManagement::with(['project.tl', 'assignedEmployee'])
            ->assignedToEmployee((int) $employee->id)
            ->where('id', $id)
            ->first();

        if (!$task) {
            return response()->json([
                'status' => false,
                'message' => 'Task management record not found for this employee.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'My task management record fetched successfully.',
            'data' => $this->transformTask($task),
        ]);
    }

    private function transformTask(TaskManagement $task): array
    {
        return [
            'id' => (int) $task->id,
            'project_id' => (int) $task->project_id,
            'task_name' => $task->task_name,
            'type' => $task->type,
            'priority' => $task->priority,
            'start_date' => $task->start_date,
            'end_date' => $task->end_date,
            'assigned_to' => (int) $task->assigned_to,
            'created_at' => $task->created_at,
            'updated_at' => $task->updated_at,
            'project' => $task->project ? [
                'id' => (int) $task->project->id,
                'project_code' => $task->project->project_code,
                'title' => $task->project->title,
                'deadline' => $task->project->deadline,
                'status' => $task->project->status,
                'tl_id' => (int) $task->project->tl_id,
            ] : null,
            'assigned_employee' => $this->transformEmployee($task->assignedEmployee),
        ];
    }

    private function transformEmployee(?Employee $employee): ?array
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

    private function authenticatedEmployeeFromToken(Request $request): ?Employee
    {
        $token = $request->bearerToken();
        if (!$token) {
            return null;
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload) {
            return null;
        }

        $role = str_replace([' ', '-'], '_', strtolower(trim((string) ($payload['role'] ?? ''))));
        if (!in_array($role, ['employee', 'tl', 'team_lead'], true)) {
            return null;
        }

        $employeeId = (int) ($payload['sub'] ?? 0);
        if ($employeeId <= 0) {
            return null;
        }

        return Employee::find($employeeId);
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

        $blacklistKey = 'employee_jwt_blacklist:' . hash('sha256', $token);
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
}
