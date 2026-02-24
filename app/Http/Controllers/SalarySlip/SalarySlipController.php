<?php

namespace App\Http\Controllers\SalarySlip;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Attendence;
use App\Models\Employee;
use App\Models\EmployeePayroll;
use App\Models\SalarySlip;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class SalarySlipController extends Controller
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
            'employee_id' => ['nullable', 'integer', 'exists:employees,id'],
            'month' => ['nullable', 'string', 'max:20'],
            'year' => ['nullable', 'integer', 'min:2000', 'max:2100'],
        ]);

        $query = SalarySlip::query();

        if (!empty($validated['employee_id'])) {
            $query->where('employee_id', (int) $validated['employee_id']);
        }
        if (!empty($validated['month'])) {
            $normalizedMonth = $this->normalizeMonth($validated['month']);
            if ($normalizedMonth === null) {
                return response()->json([
                    'status' => false,
                    'message' => 'Invalid month. Use month names like january, february, march.',
                ], 422);
            }

            $query->where('month', $normalizedMonth);
        }
        if (!empty($validated['year'])) {
            $query->where('year', (int) $validated['year']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $employeeIds = Employee::query()
                ->where('emp_name', 'like', '%' . $search . '%')
                ->orWhere('emp_email', 'like', '%' . $search . '%')
                ->pluck('id');

            $query->where(function ($builder) use ($search, $employeeIds) {
                $builder->whereIn('employee_id', $employeeIds)
                    ->orWhereRaw("JSON_SEARCH(deductions, 'one', ?) IS NOT NULL", [$search])
                    ->orWhere('month', 'like', '%' . $search . '%')
                    ->orWhere('year', 'like', '%' . $search . '%');
            });
        }

        $salarySlips = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Salary slips fetched successfully.',
            'data' => $this->transformSalarySlips($salarySlips->items()),
            'pagination' => [
                'current_page' => $salarySlips->currentPage(),
                'last_page' => $salarySlips->lastPage(),
                'per_page' => $salarySlips->perPage(),
                'total' => $salarySlips->total(),
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
            'employee_id' => ['required', 'integer', 'exists:employees,id'],
            'deductions' => ['required', 'array', 'min:1'],
            'deductions.*.deduction_type' => ['required', 'string', 'max:100'],
            'deductions.*.amount' => ['required', 'numeric', 'min:0'],
            'month' => ['required', 'string', 'max:20'],
            'year' => ['required', 'integer', 'min:2000', 'max:2100'],
        ]);

        $normalizedMonth = $this->normalizeMonth($validated['month']);
        if ($normalizedMonth === null) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid month. Use month names like january, february, march.',
            ], 422);
        }

        $deductions = array_map(function ($item) {
            return [
                'deduction_type' => (string) $item['deduction_type'],
                'amount' => (float) $item['amount'],
            ];
        }, $validated['deductions']);

        $salarySlip = new SalarySlip();
        $salarySlip->slip_code = $this->generateSlipCode((int) $validated['year']);
        $salarySlip->employee_id = $validated['employee_id'];
        $salarySlip->deductions = $deductions;
        $salarySlip->month = $normalizedMonth;
        $salarySlip->year = $validated['year'];
        $salarySlip->generated_by = $admin->id;
        $salarySlip->save();

        return response()->json([
            'status' => true,
            'message' => 'Salary slip created successfully.',
            'data' => $this->transformSalarySlips([$salarySlip])[0],
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

        $salarySlip = SalarySlip::find($id);
        if (!$salarySlip) {
            return response()->json([
                'status' => false,
                'message' => 'Salary slip not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Salary slip fetched successfully.',
            'data' => $this->buildDetailedSalarySlip($salarySlip),
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

        $salarySlip = SalarySlip::find($id);
        if (!$salarySlip) {
            return response()->json([
                'status' => false,
                'message' => 'Salary slip not found.',
            ], 404);
        }

        $validated = $request->validate([
            'employee_id' => ['sometimes', 'required', 'integer', 'exists:employees,id'],
            'deductions' => ['sometimes', 'required', 'array', 'min:1'],
            'deductions.*.deduction_type' => ['required', 'string', 'max:100'],
            'deductions.*.amount' => ['required', 'numeric', 'min:0'],
            'month' => ['sometimes', 'required', 'string', 'max:20'],
            'year' => ['sometimes', 'required', 'integer', 'min:2000', 'max:2100'],
        ]);

        if (array_key_exists('month', $validated)) {
            $normalizedMonth = $this->normalizeMonth($validated['month']);
            if ($normalizedMonth === null) {
                return response()->json([
                    'status' => false,
                    'message' => 'Invalid month. Use month names like january, february, march.',
                ], 422);
            }

            $validated['month'] = $normalizedMonth;
        }

        if (array_key_exists('employee_id', $validated)) {
            $salarySlip->employee_id = $validated['employee_id'];
        }
        if (array_key_exists('deductions', $validated)) {
            $salarySlip->deductions = array_map(function ($item) {
                return [
                    'deduction_type' => (string) $item['deduction_type'],
                    'amount' => (float) $item['amount'],
                ];
            }, $validated['deductions']);
        }
        if (array_key_exists('month', $validated)) {
            $salarySlip->month = $validated['month'];
        }
        if (array_key_exists('year', $validated)) {
            $salarySlip->year = $validated['year'];
        }

        $salarySlip->generated_by = $admin->id;
        $salarySlip->save();

        return response()->json([
            'status' => true,
            'message' => 'Salary slip updated successfully.',
            'data' => $this->transformSalarySlips([$salarySlip])[0],
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

        $salarySlip = SalarySlip::find($id);
        if (!$salarySlip) {
            return response()->json([
                'status' => false,
                'message' => 'Salary slip not found.',
            ], 404);
        }

        $salarySlip->delete();

        return response()->json([
            'status' => true,
            'message' => 'Salary slip deleted successfully.',
        ]);
    }

    private function transformSalarySlips(array $salarySlips): array
    {
        $employeeIds = collect($salarySlips)->pluck('employee_id')->filter()->unique()->values();
        $adminIds = collect($salarySlips)->pluck('generated_by')->filter()->unique()->values();

        $employees = Employee::whereIn('id', $employeeIds)->get()->keyBy('id');
        $admins = Admin::whereIn('id', $adminIds)->get()->keyBy('id');

        return array_map(function (SalarySlip $salarySlip) use ($employees, $admins) {
            $employee = $employees->get($salarySlip->employee_id);
            $generatedBy = $admins->get($salarySlip->generated_by);

            return [
                'id' => $salarySlip->id,
                'slip_code' => $salarySlip->slip_code,
                'employee_id' => $salarySlip->employee_id,
                'deductions' => $salarySlip->deductions ?? [],
                'month' => $salarySlip->month,
                'year' => $salarySlip->year,
                'generated_by' => $salarySlip->generated_by,
                'created_at' => $salarySlip->created_at,
                'updated_at' => $salarySlip->updated_at,
                'employee' => $employee ? [
                    'id' => $employee->id,
                    'emp_name' => $employee->emp_name,
                    'emp_email' => $employee->emp_email,
                ] : null,
                'generated_admin' => $generatedBy ? [
                    'id' => $generatedBy->id,
                    'full_name' => $generatedBy->full_name,
                    'email' => $generatedBy->email,
                ] : null,
            ];
        }, $salarySlips);
    }

    private function buildDetailedSalarySlip(SalarySlip $salarySlip): array
    {
        $base = $this->transformSalarySlips([$salarySlip])[0];
        $employee = Employee::find($salarySlip->employee_id);
        $payroll = EmployeePayroll::where('employee_id', $salarySlip->employee_id)->latest('id')->first();

        $monthNumber = $this->monthNumberFromName((string) $salarySlip->month);
        $attendanceRecords = collect();
        $attendanceSummary = [
            'present' => 0,
            'halfday' => 0,
            'holiday' => 0,
            'absent' => 0,
        ];
        $totalDaysInMonth = 0;
        $payableDays = 0.0;

        if ($monthNumber !== null) {
            $attendanceRecords = Attendence::query()
                ->where('employee_id', $salarySlip->employee_id)
                ->whereYear('date', (int) $salarySlip->year)
                ->whereMonth('date', $monthNumber)
                ->orderBy('date')
                ->get();

            foreach ($attendanceRecords as $attendance) {
                $status = (string) $attendance->status;
                if (array_key_exists($status, $attendanceSummary)) {
                    $attendanceSummary[$status]++;
                }
            }

            $totalDaysInMonth = Carbon::create((int) $salarySlip->year, $monthNumber, 1)->daysInMonth;
            $payableDays = (float) $attendanceSummary['present']
                + (float) $attendanceSummary['holiday']
                + ((float) $attendanceSummary['halfday'] * 0.5);
        }

        $basicSalary = (float) ($payroll?->basic_salary ?? 0);
        $hra = (float) ($payroll?->hra ?? 0);
        $medicalAllowance = (float) ($payroll?->medical_allowance ?? 0);
        $conveyanceAllowance = (float) ($payroll?->conveyance_allowance ?? 0);
        $grossSalary = $basicSalary + $hra + $medicalAllowance + $conveyanceAllowance;
        $perDaySalary = $totalDaysInMonth > 0 ? ($grossSalary / $totalDaysInMonth) : 0;
        $totalAttendanceEntries = array_sum($attendanceSummary);
        $grossPayableSalary = $totalAttendanceEntries > 0
            ? round($perDaySalary * $payableDays, 2)
            : round($grossSalary, 2);
        $totalDeductions = round(
            (float) collect($salarySlip->deductions ?? [])->sum(fn ($item) => (float) ($item['amount'] ?? 0)),
            2
        );
        $netSalary = round($grossPayableSalary - $totalDeductions, 2);
        $finalSalaryPayable = round(max($netSalary, 0), 2);

        $base['employee_code'] = $employee?->emp_code;
        $base['joining_date'] = $employee && !empty($employee->joining_date)
            ? Carbon::parse($employee->joining_date)->format('d M Y')
            : null;
        $base['generated_at'] = optional($salarySlip->created_at)->format('Y-m-d H:i:s');
        $base['attendance_records'] = $attendanceRecords->map(function (Attendence $attendance) {
            return [
                'id' => $attendance->id,
                'date' => $attendance->date,
                'status' => $attendance->status,
                'mark_in' => $attendance->mark_in,
                'mark_out' => $attendance->mark_out,
                'break_start' => $attendance->break_start,
                'break_end' => $attendance->break_end,
            ];
        })->values()->all();
        $base['attendance_summary'] = $attendanceSummary;
        $base['employee_payroll'] = [
            'basic_salary' => $payroll?->basic_salary,
            'hra' => $payroll?->hra,
            'medical_allowance' => $payroll?->medical_allowance,
            'conveyance_allowance' => $payroll?->conveyance_allowance,
        ];
        $base['salary_calculation'] = [
            'total_days_in_month' => $totalDaysInMonth,
            'payable_days' => $payableDays,
            'per_day_salary' => round($perDaySalary, 2),
            'gross_salary' => round($grossSalary, 2),
            'gross_payable_salary' => $grossPayableSalary,
            'total_deductions' => $totalDeductions,
            'net_salary' => $netSalary,
            'final_salary_payable' => $finalSalaryPayable,
        ];

        return $base;
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

    private function normalizeMonth(string $month): ?string
    {
        $normalized = strtolower(trim($month));
        $validMonths = [
            'january',
            'february',
            'march',
            'april',
            'may',
            'june',
            'july',
            'august',
            'september',
            'october',
            'november',
            'december',
        ];

        return in_array($normalized, $validMonths, true) ? $normalized : null;
    }

    private function monthNumberFromName(string $month): ?int
    {
        $map = [
            'january' => 1,
            'february' => 2,
            'march' => 3,
            'april' => 4,
            'may' => 5,
            'june' => 6,
            'july' => 7,
            'august' => 8,
            'september' => 9,
            'october' => 10,
            'november' => 11,
            'december' => 12,
        ];

        $normalized = strtolower(trim($month));
        return $map[$normalized] ?? null;
    }

    private function generateSlipCode(int $year): string
    {
        $prefix = "BT/HR/{$year}";
        $latestSlipCode = SalarySlip::query()
            ->where('slip_code', 'like', $prefix . '/%')
            ->orderByDesc('id')
            ->value('slip_code');

        $nextSequence = 1;
        if (is_string($latestSlipCode) && preg_match('/\/(\d{4})$/', $latestSlipCode, $matches)) {
            $nextSequence = ((int) $matches[1]) + 1;
        }

        $candidate = sprintf('%s/%04d', $prefix, $nextSequence);
        while (SalarySlip::where('slip_code', $candidate)->exists()) {
            $nextSequence++;
            $candidate = sprintf('%s/%04d', $prefix, $nextSequence);
        }

        return $candidate;
    }
}
