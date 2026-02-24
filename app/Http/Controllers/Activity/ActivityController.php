<?php

namespace App\Http\Controllers\Activity;

use App\Http\Controllers\Controller;
use App\Models\Activity;
use App\Models\Admin;
use App\Models\BestEmployee;
use App\Models\Employee;
use App\Models\EvaluationCriteria;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class ActivityController extends Controller
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
            'status' => ['nullable', 'in:pending,active,completed'],
            'employee_id' => ['nullable', 'integer', 'exists:employees,id'],
        ]);

        $query = Activity::query();

        if (!empty($validated['status'])) {
            $query->where('status', $validated['status']);
        }

        if (!empty($validated['employee_id'])) {
            $employeeId = (int) $validated['employee_id'];
            $query->where(function ($builder) use ($employeeId) {
                $builder->where('employee_id', $employeeId)
                    ->orWhereJsonContains('employee_ids', $employeeId);
            });
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('title', 'like', '%' . $search . '%')
                    ->orWhere('description', 'like', '%' . $search . '%')
                    ->orWhere('status', 'like', '%' . $search . '%')
                    ->orWhere('who_can_give_points', 'like', '%' . $search . '%')
                    ->orWhere('max_points', 'like', '%' . $search . '%');
            });
        }

        $activities = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Activities fetched successfully.',
            'data' => $this->transformActivities($activities->items()),
            'pagination' => [
                'current_page' => $activities->currentPage(),
                'last_page' => $activities->lastPage(),
                'per_page' => $activities->perPage(),
                'total' => $activities->total(),
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
            'title' => ['required', 'string', 'max:255'],
            'employee_ids' => ['required', 'array', 'min:1'],
            'employee_ids.*' => ['required', 'integer', 'distinct', 'exists:employees,id'],
            'description' => ['nullable', 'string'],
            'date_time' => ['required', 'date'],
            'status' => ['nullable', 'in:pending,active,completed'],
            'who_can_give_points' => ['nullable', 'string', 'max:255'],
            'max_points' => ['required', 'numeric', 'min:0'],
            'criteria' => ['required', 'array', 'min:1'],
            'criteria.*.eva_name' => ['required', 'string', 'max:255'],
            'criteria.*.eva_description' => ['nullable', 'string'],
            'best_employee' => ['nullable', 'array'],
            'best_employee.employee_id' => ['required_with:best_employee', 'integer', 'exists:employees,id'],
            'best_employee.description' => ['nullable', 'string'],
        ]);

        try {
            $activity = DB::transaction(function () use ($validated) {
                $activity = new Activity();
                $activity->title = $validated['title'];
                $activity->employee_id = (int) $validated['employee_ids'][0];
                $activity->employee_ids = array_values(array_unique(array_map('intval', $validated['employee_ids'])));
                $activity->description = $validated['description'] ?? null;
                $activity->date_time = $validated['date_time'];
                $activity->status = $validated['status'] ?? 'pending';
                $activity->who_can_give_points = $validated['who_can_give_points'] ?? null;
                $activity->max_points = $validated['max_points'];
                $activity->save();

                foreach ($validated['criteria'] as $criteriaItem) {
                $criteria = new EvaluationCriteria();
                $criteria->activity_id = $activity->id;
                $criteria->eva_name = $criteriaItem['eva_name'];
                $criteria->eva_description = $criteriaItem['eva_description'] ?? null;
                $criteria->save();
            }

                if (!empty($validated['best_employee'])) {
                    if (!in_array((int) $validated['best_employee']['employee_id'], $activity->employee_ids ?? [], true)) {
                        throw new \RuntimeException('Best employee must be one of selected activity employees.');
                    }

                    $bestEmployee = new BestEmployee();
                    $bestEmployee->activity_id = $activity->id;
                    $bestEmployee->employee_id = $validated['best_employee']['employee_id'];
                    $bestEmployee->description = $validated['best_employee']['description'] ?? null;
                    $bestEmployee->save();
                }

                return $activity->fresh();
            });

            return response()->json([
                'status' => true,
                'message' => 'Activity created successfully.',
                'data' => $this->transformActivities([$activity])[0],
            ], 201);
        } catch (\RuntimeException $exception) {
            return response()->json([
                'status' => false,
                'message' => $exception->getMessage(),
            ], 422);
        }
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

        $activity = Activity::find($id);
        if (!$activity) {
            return response()->json([
                'status' => false,
                'message' => 'Activity not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Activity fetched successfully.',
            'data' => $this->transformActivities([$activity])[0],
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

        $activity = Activity::find($id);
        if (!$activity) {
            return response()->json([
                'status' => false,
                'message' => 'Activity not found.',
            ], 404);
        }

        $validated = $request->validate([
            'title' => ['sometimes', 'required', 'string', 'max:255'],
            'employee_ids' => ['sometimes', 'required', 'array', 'min:1'],
            'employee_ids.*' => ['required', 'integer', 'distinct', 'exists:employees,id'],
            'description' => ['nullable', 'string'],
            'date_time' => ['sometimes', 'required', 'date'],
            'status' => ['nullable', 'in:pending,active,completed'],
            'who_can_give_points' => ['nullable', 'string', 'max:255'],
            'max_points' => ['sometimes', 'required', 'numeric', 'min:0'],
            'criteria' => ['required', 'array', 'min:1'],
            'criteria.*.eva_name' => ['required', 'string', 'max:255'],
            'criteria.*.eva_description' => ['nullable', 'string'],
            'best_employee' => ['nullable', 'array'],
            'best_employee.employee_id' => ['required_with:best_employee', 'integer', 'exists:employees,id'],
            'best_employee.description' => ['nullable', 'string'],
        ]);

        try {
            $updatedActivity = DB::transaction(function () use ($activity, $validated) {
                if (array_key_exists('title', $validated)) {
                    $activity->title = $validated['title'];
                }
                if (array_key_exists('employee_ids', $validated)) {
                    $normalizedEmployeeIds = array_values(array_unique(array_map('intval', $validated['employee_ids'])));
                    $activity->employee_id = (int) $normalizedEmployeeIds[0];
                    $activity->employee_ids = $normalizedEmployeeIds;
                }
                if (array_key_exists('description', $validated)) {
                    $activity->description = $validated['description'];
                }
                if (array_key_exists('date_time', $validated)) {
                    $activity->date_time = $validated['date_time'];
                }
                if (array_key_exists('status', $validated)) {
                    $activity->status = $validated['status'] ?? 'pending';
                }
                if (array_key_exists('who_can_give_points', $validated)) {
                    $activity->who_can_give_points = $validated['who_can_give_points'];
                }
                if (array_key_exists('max_points', $validated)) {
                    $activity->max_points = $validated['max_points'];
                }
                $activity->save();

                EvaluationCriteria::where('activity_id', $activity->id)->delete();
                foreach ($validated['criteria'] as $criteriaItem) {
                    $criteria = new EvaluationCriteria();
                    $criteria->activity_id = $activity->id;
                    $criteria->eva_name = $criteriaItem['eva_name'];
                    $criteria->eva_description = $criteriaItem['eva_description'] ?? null;
                    $criteria->save();
                }

                if (array_key_exists('best_employee', $validated) && !empty($validated['best_employee'])) {
                    $candidateIds = $activity->employee_ids ?? [];
                    if (!in_array((int) $validated['best_employee']['employee_id'], $candidateIds, true)) {
                        throw new \RuntimeException('Best employee must be one of selected activity employees.');
                    }

                    $bestEmployee = BestEmployee::where('activity_id', $activity->id)->first();
                    if (!$bestEmployee) {
                        $bestEmployee = new BestEmployee();
                        $bestEmployee->activity_id = $activity->id;
                    }

                    $bestEmployee->employee_id = $validated['best_employee']['employee_id'];
                    $bestEmployee->description = $validated['best_employee']['description'] ?? null;
                    $bestEmployee->save();
                }

                return $activity->fresh();
            });
        } catch (\RuntimeException $exception) {
            return response()->json([
                'status' => false,
                'message' => $exception->getMessage(),
            ], 422);
        }

        return response()->json([
            'status' => true,
            'message' => 'Activity updated successfully.',
            'data' => $this->transformActivities([$updatedActivity])[0],
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

        $activity = Activity::find($id);
        if (!$activity) {
            return response()->json([
                'status' => false,
                'message' => 'Activity not found.',
            ], 404);
        }

        $activity->delete();

        return response()->json([
            'status' => true,
            'message' => 'Activity deleted successfully.',
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

        $criteriaByActivity = EvaluationCriteria::whereIn('activity_id', $activityIds)
            ->get()
            ->groupBy('activity_id');

        $bestByActivity = BestEmployee::whereIn('activity_id', $activityIds)
            ->get()
            ->keyBy('activity_id');

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
                    $employee = $employees->get((int) $employeeId);
                    if (!$employee) {
                        return null;
                    }

                    return [
                        'id' => $employee->id,
                        'emp_name' => $employee->emp_name,
                        'emp_email' => $employee->emp_email,
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
}
