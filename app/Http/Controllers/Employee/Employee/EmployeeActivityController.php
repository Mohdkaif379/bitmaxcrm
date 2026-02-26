<?php

namespace App\Http\Controllers\Employee\Employee;

use App\Http\Controllers\Controller;
use App\Models\Activity;
use App\Models\BestEmployee;
use App\Models\Employee;
use App\Models\EvaluationCriteria;
use App\Models\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class EmployeeActivityController extends Controller
{
    public function myActivities(Request $request)
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
            'status' => ['nullable', 'in:pending,active,completed'],
        ]);

        $query = Activity::query()
            ->where(function ($builder) use ($employee) {
                $builder->where('employee_id', $employee->id)
                    ->orWhereJsonContains('employee_ids', $employee->id);
            });

        if (!empty($validated['status'])) {
            $query->where('status', $validated['status']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('title', 'like', '%' . $search . '%')
                    ->orWhere('description', 'like', '%' . $search . '%')
                    ->orWhere('status', 'like', '%' . $search . '%');
            });
        }

        $activities = $query->latest()->paginate(10);
        $this->logEmployeeActivityView($request, $employee);

        return response()->json([
            'status' => true,
            'message' => 'Assigned activities fetched successfully.',
            'data' => $this->transformActivities($activities->items()),
            'pagination' => [
                'current_page' => $activities->currentPage(),
                'last_page' => $activities->lastPage(),
                'per_page' => $activities->perPage(),
                'total' => $activities->total(),
            ],
        ]);
    }

    private function transformActivities(array $activities): array
    {
        $activityIds = collect($activities)->pluck('id')->filter()->unique()->values();
        $employeeIds = collect($activities)
            ->flatMap(function (Activity $activity) {
                $ids = $activity->employee_ids;
                if (!is_array($ids) || empty($ids)) {
                    $ids = [$activity->employee_id];
                }

                return $ids;
            })
            ->filter()
            ->unique()
            ->values();

        $criteriaByActivity = EvaluationCriteria::whereIn('activity_id', $activityIds)->get()->groupBy('activity_id');
        $bestByActivity = BestEmployee::whereIn('activity_id', $activityIds)->get()->keyBy('activity_id');
        $employees = Employee::whereIn('id', $employeeIds)->get()->keyBy('id');
        $bestEmployeeIds = $bestByActivity->pluck('employee_id')->filter()->unique()->values();
        $bestEmployees = Employee::whereIn('id', $bestEmployeeIds)->get()->keyBy('id');

        return array_map(function (Activity $activity) use ($criteriaByActivity, $bestByActivity, $employees, $bestEmployees) {
            $activityEmployeeIds = $activity->employee_ids;
            if (!is_array($activityEmployeeIds) || empty($activityEmployeeIds)) {
                $activityEmployeeIds = [$activity->employee_id];
            }

            $bestRecord = $bestByActivity->get($activity->id);
            $bestRecordEmployee = $bestRecord ? $bestEmployees->get($bestRecord->employee_id) : null;

            return [
                'id' => $activity->id,
                'title' => $activity->title,
                'employee_id' => $activity->employee_id,
                'employee_ids' => array_values(array_unique(array_map('intval', $activityEmployeeIds))),
                'description' => $activity->description,
                'date_time' => $activity->date_time,
                'status' => $activity->status,
                'who_can_give_points' => $activity->who_can_give_points,
                'max_points' => $activity->max_points,
                'created_at' => $activity->created_at,
                'updated_at' => $activity->updated_at,
                'employees' => collect($activityEmployeeIds)->map(function ($employeeId) use ($employees) {
                    $activityEmployee = $employees->get((int) $employeeId);
                    if (!$activityEmployee) {
                        return null;
                    }

                    return [
                        'id' => $activityEmployee->id,
                        'emp_name' => $activityEmployee->emp_name,
                        'emp_email' => $activityEmployee->emp_email,
                    ];
                })->filter()->values()->all(),
                'criteria' => ($criteriaByActivity->get($activity->id) ?? collect())->map(function (EvaluationCriteria $criteria) {
                    return [
                        'id' => $criteria->id,
                        'eva_name' => $criteria->eva_name,
                        'eva_description' => $criteria->eva_description,
                    ];
                })->values()->all(),
                'best_employee' => $bestRecord ? [
                    'id' => $bestRecord->id,
                    'employee_id' => $bestRecord->employee_id,
                    'description' => $bestRecord->description,
                    'employee' => $bestRecordEmployee ? [
                        'id' => $bestRecordEmployee->id,
                        'emp_name' => $bestRecordEmployee->emp_name,
                        'emp_email' => $bestRecordEmployee->emp_email,
                    ] : null,
                ] : null,
            ];
        }, $activities);
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

    private function logEmployeeActivityView(Request $request, Employee $employee): void
    {
        $employeeName = $employee->emp_name ?: 'unknown employee';

        $log = new Log();
        $log->admin_id = null;
        $log->employee_id = $employee->id;
        $log->model = class_basename(Activity::class);
        $log->action = 'view';
        $log->description = sprintf(
            'employee(%s) viewed assigned activities',
            $employeeName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
