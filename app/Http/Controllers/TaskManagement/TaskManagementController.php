<?php

namespace App\Http\Controllers\TaskManagement;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Employee;
use App\Models\MemberAssign;
use App\Models\Project;
use App\Models\TaskManagement;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Validation\Rule;

class TaskManagementController extends Controller
{
    public function index(Request $request)
    {
        $actor = $this->authenticatedTaskManagerFromToken($request);
        if (!$actor) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid TL or admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
            'project_id' => ['nullable', 'integer', 'exists:projects,id'],
            'assigned_to' => ['nullable', 'integer', 'exists:employees,id'],
            'priority' => ['nullable', Rule::in(['low', 'medium', 'high'])],
            'type' => ['nullable', 'string', 'max:255'],
        ]);

        $query = TaskManagement::with(['project.tl', 'assignedEmployee']);

        if ($actor instanceof Employee) {
            $query->whereHas('project', function ($projectQuery) use ($actor) {
                $projectQuery->where('tl_id', $actor->id);
            });
        }

        if (!empty($validated['project_id'])) {
            $query->where('project_id', (int) $validated['project_id']);
        }

        if (!empty($validated['assigned_to'])) {
            $query->where('assigned_to', (int) $validated['assigned_to']);
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
                    })
                    ->orWhereHas('assignedEmployee', function ($employeeQuery) use ($search) {
                        $employeeQuery->where('emp_name', 'like', '%' . $search . '%')
                            ->orWhere('emp_code', 'like', '%' . $search . '%')
                            ->orWhere('emp_email', 'like', '%' . $search . '%');
                    });
            });
        }

        $tasks = $query->latest('id')->paginate(10);
        $data = collect($tasks->items())
            ->map(fn (TaskManagement $task) => $this->transformTask($task))
            ->values()
            ->all();

        return response()->json([
            'status' => true,
            'message' => 'Task management records fetched successfully.',
            'data' => $data,
            'pagination' => [
                'current_page' => $tasks->currentPage(),
                'last_page' => $tasks->lastPage(),
                'per_page' => $tasks->perPage(),
                'total' => $tasks->total(),
            ],
        ]);
    }

    public function store(Request $request)
    {
        $actor = $this->authenticatedTaskManagerFromToken($request);
        if (!$actor) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid TL or admin token is required.',
            ], 401);
        }

        $validated = $request->validate($this->validationRules());

        if ($response = $this->ensureTaskManagerCanManageTask($actor, (int) $validated['project_id'], (int) $validated['assigned_to'])) {
            return $response;
        }

        $validated['status'] = 'pending';
        $task = TaskManagement::create($validated);
        $task->load(['project.tl', 'assignedEmployee']);

        return response()->json([
            'status' => true,
            'message' => 'Task management record created successfully.',
            'data' => $this->transformTask($task),
        ], 201);
    }

    public function show(Request $request, int $id)
    {
        $actor = $this->authenticatedTaskManagerFromToken($request);
        if (!$actor) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid TL or admin token is required.',
            ], 401);
        }

        $task = $this->findTaskForActor($id, $actor);
        if (!$task) {
            return response()->json([
                'status' => false,
                'message' => 'Task management record not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Task management record fetched successfully.',
            'data' => $this->transformTask($task),
        ]);
    }

    public function update(Request $request, int $id)
    {
        $actor = $this->authenticatedTaskManagerFromToken($request);
        if (!$actor) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid TL or admin token is required.',
            ], 401);
        }

        $task = $this->findTaskForActor($id, $actor);
        if (!$task) {
            return response()->json([
                'status' => false,
                'message' => 'Task management record not found.',
            ], 404);
        }

        $validated = $request->validate($this->validationRules(true));

        $projectId = (int) ($validated['project_id'] ?? $task->project_id);
        $assignedTo = (int) ($validated['assigned_to'] ?? $task->assigned_to);

        if ($response = $this->ensureTaskManagerCanManageTask($actor, $projectId, $assignedTo)) {
            return $response;
        }

        $task->update($validated);
        $task->load(['project.tl', 'assignedEmployee']);

        return response()->json([
            'status' => true,
            'message' => 'Task management record updated successfully.',
            'data' => $this->transformTask($task),
        ]);
    }

    public function destroy(Request $request, int $id)
    {
        $actor = $this->authenticatedTaskManagerFromToken($request);
        if (!$actor) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid TL or admin token is required.',
            ], 401);
        }

        $task = $this->findTaskForActor($id, $actor);
        if (!$task) {
            return response()->json([
                'status' => false,
                'message' => 'Task management record not found.',
            ], 404);
        }

        $task->delete();

        return response()->json([
            'status' => true,
            'message' => 'Task management record deleted successfully.',
        ]);
    }

    private function validationRules(bool $isUpdate = false): array
    {
        $required = $isUpdate ? 'sometimes' : 'required';

        return [
            'project_id' => [$required, 'integer', 'exists:projects,id'],
            'task_name' => [$required, 'string', 'max:255'],
            'type' => ['nullable', 'string', 'max:255'],
            'priority' => [$isUpdate ? 'sometimes' : 'nullable', Rule::in(['low', 'medium', 'high'])],
            'start_date' => ['nullable', 'date'],
            'end_date' => ['nullable', 'date', 'after_or_equal:start_date'],
            'assigned_to' => [$required, 'integer', 'exists:employees,id'],
            'status' => ['nullable', 'string', 'max:255'],
        ];
    }

    private function ensureTlCanManageTask(Employee $tl, int $projectId, int $assignedTo): ?\Illuminate\Http\JsonResponse
    {
        $project = Project::find($projectId);
        if (!$project || (int) $project->tl_id !== (int) $tl->id) {
            return response()->json([
                'status' => false,
                'message' => 'You can assign tasks only for your own projects.',
            ], 403);
        }

        $employee = Employee::find($assignedTo);
        if (!$employee || $this->isTeamLeadRole($employee->role)) {
            return response()->json([
                'status' => false,
                'message' => 'Task can be assigned only to a team member, not to a TL.',
            ], 422);
        }

        $isAssignedMember = MemberAssign::where('tl_id', $tl->id)
            ->where('employee_id', $assignedTo)
            ->exists();

        if (!$isAssignedMember) {
            return response()->json([
                'status' => false,
                'message' => 'Selected employee is not assigned to your TL team.',
            ], 403);
        }

        return null;
    }

    private function ensureAdminCanManageTask(Admin $admin, int $projectId, int $assignedTo): ?\Illuminate\Http\JsonResponse
    {
        $project = Project::find($projectId);
        if (!$project) {
            return response()->json([
                'status' => false,
                'message' => 'Project not found.',
            ], 404);
        }

        $employee = Employee::find($assignedTo);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Assigned employee not found.',
            ], 404);
        }

        return null;
    }

    private function ensureTaskManagerCanManageTask(Admin|Employee $actor, int $projectId, int $assignedTo): ?\Illuminate\Http\JsonResponse
    {
        if ($actor instanceof Admin) {
            return $this->ensureAdminCanManageTask($actor, $projectId, $assignedTo);
        }

        return $this->ensureTlCanManageTask($actor, $projectId, $assignedTo);
    }

    private function findTaskForActor(int $id, Admin|Employee $actor): ?TaskManagement
    {
        if ($actor instanceof Admin) {
            return TaskManagement::with(['project.tl', 'assignedEmployee'])->find($id);
        }

        return $this->findTaskForTl($id, $actor);
    }

    private function findTaskForTl(int $id, Employee $tl): ?TaskManagement
    {
        return TaskManagement::with(['project.tl', 'assignedEmployee'])
            ->where('id', $id)
            ->whereHas('project', function ($projectQuery) use ($tl) {
                $projectQuery->where('tl_id', $tl->id);
            })
            ->first();
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
            'status' => $task->status,
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

    private function authenticatedTlFromToken(Request $request): ?Employee
    {
        $token = $request->bearerToken();
        if (!$token) {
            return null;
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload || !$this->isTeamLeadRole($payload['role'] ?? null)) {
            return null;
        }

        $employeeId = (int) ($payload['sub'] ?? 0);
        if ($employeeId <= 0) {
            return null;
        }

        $employee = Employee::find($employeeId);
        if (!$employee || !$this->isTeamLeadRole($employee->role)) {
            return null;
        }

        return $employee;
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

    private function authenticatedTaskManagerFromToken(Request $request): Admin|Employee|null
    {
        return $this->authenticatedTlFromToken($request) ?? $this->authenticatedAdminFromToken($request);
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

    private function isTeamLeadRole(?string $role): bool
    {
        $normalizedRole = str_replace([' ', '-'], '_', strtolower(trim((string) $role)));

        return in_array($normalizedRole, ['tl','TL', 'team_lead'], true);
    }
}
