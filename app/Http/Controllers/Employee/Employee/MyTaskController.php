<?php

namespace App\Http\Controllers\Employee\Employee;

use App\Http\Controllers\Controller;
use App\Models\Employee;
use App\Models\EmployeeTask;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class MyTaskController extends Controller
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
            'status' => ['nullable', 'in:not_started,pending,in_progress,completed'],
            'priority' => ['nullable', 'in:low,medium,high'],
        ]);

        $query = EmployeeTask::with(['task', 'employee'])
            ->where('employee_id', $employee->id);

        if (!empty($validated['status'])) {
            $query->whereHas('task', function ($taskQuery) use ($validated) {
                $taskQuery->where('status', $validated['status']);
            });
        }

        if (!empty($validated['priority'])) {
            $query->whereHas('task', function ($taskQuery) use ($validated) {
                $taskQuery->where('priority', $validated['priority']);
            });
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->whereHas('task', function ($taskQuery) use ($search) {
                $taskQuery->where('task_name', 'like', '%' . $search . '%')
                    ->orWhere('assignment_type', 'like', '%' . $search . '%');
            });
        }

        $assignments = $query->latest('id')->paginate(10);

        $employeeData = $employee->toArray();
        unset($employeeData['password']);

        $data = collect($assignments->items())
            ->map(function (EmployeeTask $assignment) {
                $employeeDetails = $assignment->employee ? $assignment->employee->toArray() : null;
                if (is_array($employeeDetails)) {
                    unset($employeeDetails['password']);
                }

                return [
                    'assignment_id' => $assignment->id,
                    'employee_id' => $assignment->employee_id,
                    'task_id' => $assignment->task_id,
                    'assigned_at' => $assignment->created_at,
                    'updated_at' => $assignment->updated_at,
                    'employee' => $employeeDetails,
                    'task' => $assignment->task ? $assignment->task->toArray() : null,
                ];
            })
            ->values()
            ->all();

        return response()->json([
            'status' => true,
            'message' => 'Assigned tasks fetched successfully.',
            'employee' => $employeeData,
            'data' => $data,
            'pagination' => [
                'current_page' => $assignments->currentPage(),
                'last_page' => $assignments->lastPage(),
                'per_page' => $assignments->perPage(),
                'total' => $assignments->total(),
            ],
        ]);
    }

    public function updateStatus(Request $request, int $taskId)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'status' => ['required', 'in:not_started,pending,in_progress,completed'],
        ]);

        $assignment = EmployeeTask::with(['employee', 'task'])
            ->where('employee_id', $employee->id)
            ->where('task_id', $taskId)
            ->first();

        if (!$assignment || !$assignment->task) {
            return response()->json([
                'status' => false,
                'message' => 'Assigned task not found for this employee.',
            ], 404);
        }

        $assignment->task->status = $validated['status'];
        $assignment->task->save();
        $assignment->refresh()->load(['employee', 'task']);

        $employeeData = $assignment->employee ? $assignment->employee->toArray() : null;
        if (is_array($employeeData)) {
            unset($employeeData['password']);
        }

        return response()->json([
            'status' => true,
            'message' => 'Task status updated successfully.',
            'data' => [
                'assignment_id' => $assignment->id,
                'employee_id' => $assignment->employee_id,
                'task_id' => $assignment->task_id,
                'assigned_at' => $assignment->created_at,
                'updated_at' => $assignment->updated_at,
                'employee' => $employeeData,
                'task' => $assignment->task->toArray(),
            ],
        ]);
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

        if (($payload['role'] ?? null) !== 'employee') {
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
