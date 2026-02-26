<?php

namespace App\Http\Controllers\Task;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Log;
use App\Models\Task;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class TaskController extends Controller
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
            'status' => ['nullable', 'in:not_started,pending,in_progress,completed'],
            'priority' => ['nullable', 'in:low,medium,high'],
            'search' => ['nullable', 'string', 'max:255'],
        ]);

        $query = Task::query();

        if (!empty($validated['status'])) {
            $query->where('status', $validated['status']);
        }

        if (!empty($validated['priority'])) {
            $query->where('priority', $validated['priority']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('task_name', 'like', '%' . $search . '%')
                    ->orWhere('assignment_type', 'like', '%' . $search . '%')
                    ->orWhere('status', 'like', '%' . $search . '%')
                    ->orWhere('priority', 'like', '%' . $search . '%');
            });
        }

        $tasks = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Tasks fetched successfully.',
            'data' => $tasks->items(),
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
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'task_name' => ['required', 'string', 'max:255'],
            'assignment_type' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'in:not_started,pending,in_progress,completed'],
            'start_date' => ['nullable', 'date'],
            'end_date' => ['nullable', 'date', 'after_or_equal:start_date'],
            'priority' => ['nullable', 'in:low,medium,high'],
            'progress' => ['nullable', 'integer', 'min:0', 'max:100'],
        ]);

        $task = new Task();
        $task->task_name = $validated['task_name'];
        $task->assignment_type = $validated['assignment_type'] ?? null;
        $task->status = $validated['status'] ?? 'not_started';
        $task->start_date = $validated['start_date'] ?? null;
        $task->end_date = $validated['end_date'] ?? null;
        $task->priority = $validated['priority'] ?? 'medium';
        $task->progress = $validated['progress'] ?? 0;
        $task->save();
        $this->logTaskAction($request, $admin, $task, 'create', 'created task');

        return response()->json([
            'status' => true,
            'message' => 'Task created successfully.',
            'data' => $task,
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

        $task = Task::find($id);
        if (!$task) {
            return response()->json([
                'status' => false,
                'message' => 'Task not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Task fetched successfully.',
            'data' => $task,
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

        $task = Task::find($id);
        if (!$task) {
            return response()->json([
                'status' => false,
                'message' => 'Task not found.',
            ], 404);
        }

        $validated = $request->validate([
            'task_name' => ['sometimes', 'required', 'string', 'max:255'],
            'assignment_type' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'in:not_started,pending,in_progress,completed'],
            'start_date' => ['nullable', 'date'],
            'end_date' => ['nullable', 'date'],
            'priority' => ['nullable', 'in:low,medium,high'],
            'progress' => ['nullable', 'integer', 'min:0', 'max:100'],
        ]);

        $effectiveStartDate = $validated['start_date'] ?? $task->start_date;
        $effectiveEndDate = $validated['end_date'] ?? $task->end_date;
        if (!empty($effectiveStartDate) && !empty($effectiveEndDate) && $effectiveEndDate < $effectiveStartDate) {
            return response()->json([
                'status' => false,
                'message' => 'End date must be after or equal to start date.',
            ], 422);
        }

        if (array_key_exists('task_name', $validated)) {
            $task->task_name = $validated['task_name'];
        }
        if (array_key_exists('assignment_type', $validated)) {
            $task->assignment_type = $validated['assignment_type'];
        }
        if (array_key_exists('status', $validated)) {
            $task->status = $validated['status'] ?: 'not_started';
        }
        if (array_key_exists('start_date', $validated)) {
            $task->start_date = $validated['start_date'];
        }
        if (array_key_exists('end_date', $validated)) {
            $task->end_date = $validated['end_date'];
        }
        if (array_key_exists('priority', $validated)) {
            $task->priority = $validated['priority'] ?: 'medium';
        }
        if (array_key_exists('progress', $validated)) {
            $task->progress = $validated['progress'] ?? 0;
        }

        $task->save();
        $this->logTaskAction($request, $admin, $task, 'update', 'updated task');

        return response()->json([
            'status' => true,
            'message' => 'Task updated successfully.',
            'data' => $task,
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

        $task = Task::find($id);
        if (!$task) {
            return response()->json([
                'status' => false,
                'message' => 'Task not found.',
            ], 404);
        }

        $taskName = $task->task_name ?: 'unknown task';
        $task->delete();
        $this->logTaskDeleteAction($request, $admin, $taskName);

        return response()->json([
            'status' => true,
            'message' => 'Task deleted successfully.',
        ]);
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

    private function logTaskAction(
        Request $request,
        Admin $admin,
        Task $task,
        string $action,
        string $actionText
    ): void {
        $adminName = $admin->full_name ?: 'unknown admin';
        $taskName = $task->task_name ?: 'unknown task';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = null;
        $log->model = class_basename($task);
        $log->action = $action;
        $log->description = sprintf(
            'admin(%s) %s (%s)',
            $adminName,
            $actionText,
            $taskName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logTaskDeleteAction(Request $request, Admin $admin, string $taskName): void
    {
        $adminName = $admin->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = null;
        $log->model = class_basename(Task::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) deleted task (%s)',
            $adminName,
            $taskName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
