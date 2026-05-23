<?php

namespace App\Http\Controllers\MyAssignMember;

use App\Http\Controllers\Controller;
use App\Models\Employee;
use App\Models\Log;
use App\Models\MemberAssign;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

class MyAssignMemberController extends Controller
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
        ]);

        $query = MemberAssign::with(['employee', 'assignedBy'])
            ->where('tl_id', $employee->id);

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->whereHas('employee', function ($employeeQuery) use ($search) {
                $employeeQuery->where('emp_name', 'like', '%' . $search . '%')
                    ->orWhere('emp_code', 'like', '%' . $search . '%')
                    ->orWhere('emp_email', 'like', '%' . $search . '%')
                    ->orWhere('emp_phone', 'like', '%' . $search . '%');
            });
        }

        $assignments = $query->latest('id')->paginate(10);
        $data = collect($assignments->items())
            ->map(fn (MemberAssign $assignment) => $this->transformAssignment($assignment))
            ->values()
            ->all();

        $this->logAssignedMembersView($request, $employee);

        return response()->json([
            'status' => true,
            'message' => 'My assigned members fetched successfully.',
            'employee' => $this->transformEmployee($employee),
            'data' => $data,
            'pagination' => [
                'current_page' => $assignments->currentPage(),
                'last_page' => $assignments->lastPage(),
                'per_page' => $assignments->perPage(),
                'total' => $assignments->total(),
            ],
        ]);
    }

    private function transformAssignment(MemberAssign $assignment): array
    {
        return [
            'assignment_id' => (int) $assignment->id,
            'tl_id' => (int) $assignment->tl_id,
            'employee_id' => (int) $assignment->employee_id,
            'assigned_by' => $assignment->assigned_by ? (int) $assignment->assigned_by : null,
            'assigned_at' => $assignment->created_at,
            'updated_at' => $assignment->updated_at,
            'member' => $this->transformEmployee($assignment->employee),
            'assigned_by_admin' => $assignment->assignedBy ? [
                'id' => (int) $assignment->assignedBy->id,
                'full_name' => $assignment->assignedBy->full_name,
                'email' => $assignment->assignedBy->email,
                'role' => $assignment->assignedBy->role,
            ] : null,
        ];
    }

    private function transformEmployee(?Employee $employee): ?array
    {
        if (!$employee) {
            return null;
        }

        $data = $employee->toArray();
        unset($data['password']);
        $data['profile_photo'] = $employee->profile_photo ? url(Storage::url($employee->profile_photo)) : null;

        return $data;
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

        $role = strtolower((string) ($payload['role'] ?? ''));
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

    private function logAssignedMembersView(Request $request, Employee $employee): void
    {
        $employeeName = $employee->emp_name ?: 'unknown employee';

        $log = new Log();
        $log->admin_id = null;
        $log->employee_id = $employee->id;
        $log->model = class_basename(MemberAssign::class);
        $log->action = 'view';
        $log->description = sprintf(
            'employee(%s) viewed assigned members',
            $employeeName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
