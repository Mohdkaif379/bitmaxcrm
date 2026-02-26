<?php

namespace App\Http\Controllers\Employee;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Employee;
use App\Models\EmployeeAddress;
use App\Models\EmployeeBankDetails;
use App\Models\EmployeeDocuments;
use App\Models\EmployeeExperience;
use App\Models\EmployeeFamilyDetails;
use App\Models\Log;
use App\Models\EmployeePayroll;
use App\Models\EmployeeQualification;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\Rule;

class EmployeeController extends Controller
{
    public function index(Request $request)
    {
        if ($authResponse = $this->ensureAdminAuthorized($request)) {
            return $authResponse;
        }

        $employees = Employee::with([
            'familyDetails',
            'bankDetails',
            'payrolls',
            'qualifications',
            'addresses',
            'documents',
            'experiences',
        ])->latest()->get();

        return response()->json([
            'status' => true,
            'message' => 'Employees fetched successfully.',
            'data' => $employees->map(fn (Employee $employee) => $this->transformEmployee($employee)),
        ]);
    }

    public function store(Request $request)
    {
        if ($authResponse = $this->ensureAdminAuthorized($request)) {
            return $authResponse;
        }

        $validated = $this->validateEmployee($request);

        $employee = DB::transaction(function () use ($request, $validated) {
            $employee = new Employee();
            $employee->emp_code = $validated['emp_code'];
            $employee->emp_name = $validated['emp_name'];
            $employee->emp_email = $validated['emp_email'];
            $employee->emp_phone = $validated['emp_phone'] ?? null;
            $employee->joining_date = $validated['joining_date'] ?? null;
            $employee->dob = $validated['dob'] ?? null;
            $employee->position = $validated['position'] ?? null;
            $employee->department = $validated['department'] ?? null;
            $employee->status = $validated['status'] ?? 'active';
            $employee->role = $validated['role'] ?? 'employee';
            $employee->password = Hash::make($validated['password']);
            $employee->profile_photo = $request->hasFile('profile_photo')
                ? $request->file('profile_photo')->store('employees/profile_photos', 'public')
                : null;
            $employee->save();

            $this->syncFamilyDetails($request, $employee);
            $this->syncBankDetails($request, $employee);
            $this->syncPayrolls($request, $employee);
            $this->syncQualifications($request, $employee);
            $this->syncAddresses($request, $employee);
            $this->syncDocuments($request, $employee);
            $this->syncExperiences($request, $employee);

            return $employee->load([
                'familyDetails',
                'bankDetails',
                'payrolls',
                'qualifications',
                'addresses',
                'documents',
                'experiences',
            ]);
        });

        $this->logEmployeeAction($request, $employee, 'create', 'created employee');

        return response()->json([
            'status' => true,
            'message' => 'Employee created successfully.',
            'data' => $this->transformEmployee($employee),
        ], 201);
    }

    public function show(Request $request, $id)
    {
        if ($authResponse = $this->ensureAdminAuthorized($request)) {
            return $authResponse;
        }

        $employee = Employee::with([
            'familyDetails',
            'bankDetails',
            'payrolls',
            'qualifications',
            'addresses',
            'documents',
            'experiences',
        ])->find($id);

        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Employee not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Employee fetched successfully.',
            'data' => $this->transformEmployee($employee),
        ]);
    }

    public function update(Request $request, $id)
    {
        if ($authResponse = $this->ensureAdminAuthorized($request)) {
            return $authResponse;
        }

        $employee = Employee::with([
            'familyDetails',
            'bankDetails',
            'payrolls',
            'qualifications',
            'addresses',
            'documents',
            'experiences',
        ])->find($id);

        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Employee not found.',
            ], 404);
        }

        $validated = $this->validateEmployee($request, $employee->id);

        $employee = DB::transaction(function () use ($request, $validated, $employee) {
            if (array_key_exists('emp_code', $validated)) {
                $employee->emp_code = $validated['emp_code'];
            }

            if (array_key_exists('emp_name', $validated)) {
                $employee->emp_name = $validated['emp_name'];
            }

            if (array_key_exists('emp_email', $validated)) {
                $employee->emp_email = $validated['emp_email'];
            }

            if (array_key_exists('emp_phone', $validated)) {
                $employee->emp_phone = $validated['emp_phone'];
            }

            if (array_key_exists('joining_date', $validated)) {
                $employee->joining_date = $validated['joining_date'];
            }

            if (array_key_exists('dob', $validated)) {
                $employee->dob = $validated['dob'];
            }

            if (array_key_exists('position', $validated)) {
                $employee->position = $validated['position'];
            }

            if (array_key_exists('department', $validated)) {
                $employee->department = $validated['department'];
            }

            if (array_key_exists('status', $validated)) {
                $employee->status = $validated['status'];
            }

            if (array_key_exists('role', $validated)) {
                $employee->role = $validated['role'];
            }

            if (array_key_exists('password', $validated)) {
                $employee->password = Hash::make($validated['password']);
            }

            if ($request->hasFile('profile_photo')) {
                if ($employee->profile_photo && Storage::disk('public')->exists($employee->profile_photo)) {
                    Storage::disk('public')->delete($employee->profile_photo);
                }

                $employee->profile_photo = $request->file('profile_photo')->store('employees/profile_photos', 'public');
            }

            $employee->save();

            $this->syncFamilyDetails($request, $employee);
            $this->syncBankDetails($request, $employee);
            $this->syncPayrolls($request, $employee);
            $this->syncQualifications($request, $employee);
            $this->syncAddresses($request, $employee);
            $this->syncDocuments($request, $employee);
            $this->syncExperiences($request, $employee);

            return $employee->load([
                'familyDetails',
                'bankDetails',
                'payrolls',
                'qualifications',
                'addresses',
                'documents',
                'experiences',
            ]);
        });

        $this->logEmployeeAction($request, $employee, 'update', 'updated employee');

        return response()->json([
            'status' => true,
            'message' => 'Employee updated successfully.',
            'data' => $this->transformEmployee($employee),
        ]);
    }

    public function destroy(Request $request, $id)
    {
        if ($authResponse = $this->ensureAdminAuthorized($request)) {
            return $authResponse;
        }

        $employee = Employee::with([
            'familyDetails',
            'documents',
        ])->find($id);

        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Employee not found.',
            ], 404);
        }

        $employeeId = $employee->id;
        $employeeName = $employee->emp_name ?: 'unknown employee';

        DB::transaction(function () use ($employee) {
            if ($employee->profile_photo && Storage::disk('public')->exists($employee->profile_photo)) {
                Storage::disk('public')->delete($employee->profile_photo);
            }

            foreach ($employee->familyDetails as $familyDetail) {
                if ($familyDetail->aadhar_profile && Storage::disk('public')->exists($familyDetail->aadhar_profile)) {
                    Storage::disk('public')->delete($familyDetail->aadhar_profile);
                }

                if ($familyDetail->pan_profile && Storage::disk('public')->exists($familyDetail->pan_profile)) {
                    Storage::disk('public')->delete($familyDetail->pan_profile);
                }
            }

            foreach ($employee->documents as $document) {
                if ($document->file && Storage::disk('public')->exists($document->file)) {
                    Storage::disk('public')->delete($document->file);
                }
            }

            $employee->delete();
        });

        $this->logEmployeeDeleteAction($request, $employeeId, $employeeName);

        return response()->json([
            'status' => true,
            'message' => 'Employee deleted successfully.',
        ]);
    }

    private function validateEmployee(Request $request, ?int $employeeId = null): array
    {
        $required = $employeeId ? 'sometimes' : 'required';

        return $request->validate([
            'emp_code' => [$required, 'string', 'max:255', Rule::unique('employees', 'emp_code')->ignore($employeeId)],
            'emp_name' => [$required, 'string', 'max:255'],
            'emp_email' => [$required, 'email', 'max:255', Rule::unique('employees', 'emp_email')->ignore($employeeId)],
            'emp_phone' => ['nullable', 'string', 'max:20'],
            'joining_date' => ['nullable', 'date'],
            'dob' => ['nullable', 'date'],
            'position' => ['nullable', 'string', 'max:255'],
            'department' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'string', 'max:100'],
            'role' => ['nullable', 'string', 'max:100'],
            'password' => [$required, 'string', 'min:6'],
            'profile_photo' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:2048'],

            'family_details' => ['nullable', 'array'],
            'family_details.*.id' => ['nullable', 'integer'],
            'family_details.*.name' => ['nullable', 'string', 'max:255'],
            'family_details.*.relationship' => ['nullable', 'string', 'max:255'],
            'family_details.*.contact' => ['nullable', 'string', 'max:50'],
            'family_details.*.aadhar_number' => ['nullable', 'string', 'max:255'],
            'family_details.*.aadhar_profile' => ['nullable', 'file', 'mimes:jpg,jpeg,png,pdf,webp', 'max:5120'],
            'family_details.*.pan_number' => ['nullable', 'string', 'max:255'],
            'family_details.*.pan_profile' => ['nullable', 'file', 'mimes:jpg,jpeg,png,pdf,webp', 'max:5120'],

            'bank_details' => ['nullable', 'array'],
            'bank_details.*.id' => ['nullable', 'integer'],
            'bank_details.*.bank_name' => ['nullable', 'string', 'max:255'],
            'bank_details.*.account_number' => ['nullable', 'string', 'max:255'],
            'bank_details.*.ifsc_code' => ['nullable', 'string', 'max:255'],
            'bank_details.*.branch_name' => ['nullable', 'string', 'max:255'],

            'payrolls' => ['nullable', 'array'],
            'payrolls.*.id' => ['nullable', 'integer'],
            'payrolls.*.basic_salary' => ['nullable', 'numeric'],
            'payrolls.*.hra' => ['nullable', 'numeric'],
            'payrolls.*.conveyance_allowance' => ['nullable', 'numeric'],
            'payrolls.*.medical_allowance' => ['nullable', 'numeric'],

            'qualifications' => ['nullable', 'array'],
            'qualifications.*.id' => ['nullable', 'integer'],
            'qualifications.*.degree' => ['nullable', 'string', 'max:255'],
            'qualifications.*.institution' => ['nullable', 'string', 'max:255'],
            'qualifications.*.passing_year' => ['nullable', 'string', 'max:50'],
            'qualifications.*.grade' => ['nullable', 'string', 'max:50'],

            'addresses' => ['nullable', 'array'],
            'addresses.*.id' => ['nullable', 'integer'],
            'addresses.*.address_type' => ['nullable', 'string', 'max:255'],
            'addresses.*.street_address' => ['nullable', 'string', 'max:255'],
            'addresses.*.city' => ['nullable', 'string', 'max:255'],
            'addresses.*.state' => ['nullable', 'string', 'max:255'],
            'addresses.*.postal_code' => ['nullable', 'string', 'max:50'],
            'addresses.*.country' => ['nullable', 'string', 'max:255'],

            'documents' => ['nullable', 'array'],
            'documents.*.id' => ['nullable', 'integer'],
            'documents.*.document_type' => ['nullable', 'string', 'max:255'],
            'documents.*.file' => ['nullable', 'file', 'mimes:jpg,jpeg,png,pdf,doc,docx,webp', 'max:5120'],

            'experiences' => ['nullable', 'array'],
            'experiences.*.id' => ['nullable', 'integer'],
            'experiences.*.company_name' => ['nullable', 'string', 'max:255'],
            'experiences.*.position' => ['nullable', 'string', 'max:255'],
            'experiences.*.start_date' => ['nullable', 'date'],
            'experiences.*.end_date' => ['nullable', 'date'],
        ]);
    }

    private function syncFamilyDetails(Request $request, Employee $employee): void
    {
        if (!$request->has('family_details')) {
            return;
        }

        foreach ($request->input('family_details', []) as $index => $item) {
            $isExisting = isset($item['id']);
            $record = $isExisting
                ? EmployeeFamilyDetails::where('id', $item['id'])->where('employee_id', $employee->id)->first()
                : new EmployeeFamilyDetails();

            if (!$record) {
                continue;
            }

            if (
                !$isExisting
                && (!isset($item['name']) || $item['name'] === '' || !isset($item['relationship']) || $item['relationship'] === '')
            ) {
                continue;
            }

            $record->employee_id = $employee->id;
            if (array_key_exists('name', $item)) {
                $record->name = $item['name'];
            }

            if (array_key_exists('relationship', $item) && $item['relationship'] !== null && $item['relationship'] !== '') {
                $record->relationship = $item['relationship'];
            }

            if (array_key_exists('contact', $item)) {
                $record->contact = $item['contact'];
            }

            if (array_key_exists('aadhar_number', $item)) {
                $record->aadhar_number = $item['aadhar_number'];
            }

            if (array_key_exists('pan_number', $item)) {
                $record->pan_number = $item['pan_number'];
            }

            $aadharFile = $request->file("family_details.$index.aadhar_profile");
            if ($aadharFile) {
                if ($record->aadhar_profile && Storage::disk('public')->exists($record->aadhar_profile)) {
                    Storage::disk('public')->delete($record->aadhar_profile);
                }

                $record->aadhar_profile = $aadharFile->store('employees/family/aadhar', 'public');
            }

            $panFile = $request->file("family_details.$index.pan_profile");
            if ($panFile) {
                if ($record->pan_profile && Storage::disk('public')->exists($record->pan_profile)) {
                    Storage::disk('public')->delete($record->pan_profile);
                }

                $record->pan_profile = $panFile->store('employees/family/pan', 'public');
            }

            $record->save();
        }
    }

    private function syncBankDetails(Request $request, Employee $employee): void
    {
        if (!$request->has('bank_details')) {
            return;
        }

        foreach ($request->input('bank_details', []) as $item) {
            $isExisting = isset($item['id']);
            $record = $isExisting
                ? EmployeeBankDetails::where('id', $item['id'])->where('employee_id', $employee->id)->first()
                : new EmployeeBankDetails();

            if (!$record) {
                continue;
            }

            if (
                !$isExisting
                && (
                    !isset($item['bank_name']) || $item['bank_name'] === ''
                    || !isset($item['account_number']) || $item['account_number'] === ''
                    || !isset($item['ifsc_code']) || $item['ifsc_code'] === ''
                )
            ) {
                continue;
            }

            $record->employee_id = $employee->id;
            if (array_key_exists('bank_name', $item)) {
                $record->bank_name = $item['bank_name'];
            }

            if (array_key_exists('account_number', $item)) {
                $record->account_number = $item['account_number'];
            }

            if (array_key_exists('ifsc_code', $item) && $item['ifsc_code'] !== null && $item['ifsc_code'] !== '') {
                $record->ifsc_code = $item['ifsc_code'];
            }

            if (array_key_exists('branch_name', $item)) {
                $record->branch_name = $item['branch_name'];
            }
            $record->save();
        }
    }

    private function syncPayrolls(Request $request, Employee $employee): void
    {
        if (!$request->has('payrolls')) {
            return;
        }

        foreach ($request->input('payrolls', []) as $item) {
            $isExisting = isset($item['id']);
            $record = $isExisting
                ? EmployeePayroll::where('id', $item['id'])->where('employee_id', $employee->id)->first()
                : new EmployeePayroll();

            if (!$record) {
                continue;
            }

            if (!$isExisting && !isset($item['basic_salary'])) {
                continue;
            }

            $record->employee_id = $employee->id;
            if (array_key_exists('basic_salary', $item)) {
                $record->basic_salary = $item['basic_salary'];
            }
            if (array_key_exists('hra', $item)) {
                $record->hra = $item['hra'];
            }
            if (array_key_exists('conveyance_allowance', $item)) {
                $record->conveyance_allowance = $item['conveyance_allowance'];
            }
            if (array_key_exists('medical_allowance', $item)) {
                $record->medical_allowance = $item['medical_allowance'];
            }
            $record->save();
        }
    }

    private function syncQualifications(Request $request, Employee $employee): void
    {
        if (!$request->has('qualifications')) {
            return;
        }

        foreach ($request->input('qualifications', []) as $item) {
            $isExisting = isset($item['id']);
            $record = $isExisting
                ? EmployeeQualification::where('id', $item['id'])->where('employee_id', $employee->id)->first()
                : new EmployeeQualification();

            if (!$record) {
                continue;
            }

            if (
                !$isExisting
                && (!isset($item['degree']) || $item['degree'] === '' || !isset($item['institution']) || $item['institution'] === '')
            ) {
                continue;
            }

            $record->employee_id = $employee->id;
            if (array_key_exists('degree', $item)) {
                $record->degree = $item['degree'];
            }
            if (array_key_exists('institution', $item)) {
                $record->institution = $item['institution'];
            }
            if (array_key_exists('passing_year', $item)) {
                $record->passing_year = $item['passing_year'];
            }
            if (array_key_exists('grade', $item)) {
                $record->grade = $item['grade'];
            }
            $record->save();
        }
    }

    private function syncAddresses(Request $request, Employee $employee): void
    {
        if (!$request->has('addresses')) {
            return;
        }

        foreach ($request->input('addresses', []) as $item) {
            $isExisting = isset($item['id']);
            $record = $isExisting
                ? EmployeeAddress::where('id', $item['id'])->where('employee_id', $employee->id)->first()
                : new EmployeeAddress();

            if (!$record) {
                continue;
            }

            if (
                !$isExisting
                && (
                    !isset($item['address_type']) || $item['address_type'] === ''
                    || !isset($item['city']) || $item['city'] === ''
                    || !isset($item['state']) || $item['state'] === ''
                    || !isset($item['postal_code']) || $item['postal_code'] === ''
                    || !isset($item['country']) || $item['country'] === ''
                )
            ) {
                continue;
            }

            $record->employee_id = $employee->id;
            if (array_key_exists('address_type', $item)) {
                $record->address_type = $item['address_type'];
            }
            if (array_key_exists('street_address', $item)) {
                $record->street_address = $item['street_address'];
            }
            if (array_key_exists('city', $item)) {
                $record->city = $item['city'];
            }
            if (array_key_exists('state', $item)) {
                $record->state = $item['state'];
            }
            if (array_key_exists('postal_code', $item)) {
                $record->postal_code = $item['postal_code'];
            }
            if (array_key_exists('country', $item)) {
                $record->country = $item['country'];
            }
            $record->save();
        }
    }

    private function syncDocuments(Request $request, Employee $employee): void
    {
        if (!$request->has('documents')) {
            return;
        }

        foreach ($request->input('documents', []) as $index => $item) {
            $isExisting = isset($item['id']);
            $record = $isExisting
                ? EmployeeDocuments::where('id', $item['id'])->where('employee_id', $employee->id)->first()
                : new EmployeeDocuments();

            if (!$record) {
                continue;
            }

            if (!$isExisting && (!isset($item['document_type']) || $item['document_type'] === '')) {
                continue;
            }

            $record->employee_id = $employee->id;
            if (array_key_exists('document_type', $item)) {
                $record->document_type = $item['document_type'];
            }

            $documentFile = $request->file("documents.$index.file");
            if ($documentFile) {
                if ($record->file && Storage::disk('public')->exists($record->file)) {
                    Storage::disk('public')->delete($record->file);
                }

                $record->file = $documentFile->store('employees/documents', 'public');
            }

            $record->save();
        }
    }

    private function syncExperiences(Request $request, Employee $employee): void
    {
        if (!$request->has('experiences')) {
            return;
        }

        foreach ($request->input('experiences', []) as $item) {
            $isExisting = isset($item['id']);
            $record = $isExisting
                ? EmployeeExperience::where('id', $item['id'])->where('employee_id', $employee->id)->first()
                : new EmployeeExperience();

            if (!$record) {
                continue;
            }

            if (
                !$isExisting
                && (
                    !isset($item['company_name']) || $item['company_name'] === ''
                    || !isset($item['position']) || $item['position'] === ''
                    || !isset($item['start_date']) || $item['start_date'] === ''
                )
            ) {
                continue;
            }

            $record->employee_id = $employee->id;
            if (array_key_exists('company_name', $item)) {
                $record->company_name = $item['company_name'];
            }
            if (array_key_exists('position', $item)) {
                $record->position = $item['position'];
            }
            if (array_key_exists('start_date', $item)) {
                $record->start_date = $item['start_date'];
            }
            if (array_key_exists('end_date', $item)) {
                $record->end_date = $item['end_date'];
            }
            $record->save();
        }
    }

    private function transformEmployee(Employee $employee): array
    {
        $data = $employee->toArray();
        unset($data['password']);
        $data['profile_photo'] = $employee->profile_photo ? url(Storage::url($employee->profile_photo)) : null;

        $data['family_details'] = $employee->familyDetails->map(function (EmployeeFamilyDetails $item) {
            return [
                'id' => $item->id,
                'employee_id' => $item->employee_id,
                'name' => $item->name,
                'relationship' => $item->relationship,
                'contact' => $item->contact,
                'aadhar_number' => $item->aadhar_number,
                'aadhar_profile' => $item->aadhar_profile ? url(Storage::url($item->aadhar_profile)) : null,
                'pan_number' => $item->pan_number,
                'pan_profile' => $item->pan_profile ? url(Storage::url($item->pan_profile)) : null,
                'created_at' => $item->created_at,
                'updated_at' => $item->updated_at,
            ];
        })->values();

        $data['bank_details'] = $employee->bankDetails->values();
        $data['payrolls'] = $employee->payrolls->values();
        $data['qualifications'] = $employee->qualifications->values();
        $data['addresses'] = $employee->addresses->values();

        $data['documents'] = $employee->documents->map(function (EmployeeDocuments $item) {
            return [
                'id' => $item->id,
                'employee_id' => $item->employee_id,
                'document_type' => $item->document_type,
                'file' => $item->file ? url(Storage::url($item->file)) : null,
                'created_at' => $item->created_at,
                'updated_at' => $item->updated_at,
            ];
        })->values();

        $data['experiences'] = $employee->experiences->values();

        return $data;
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

    private function ensureAdminAuthorized(Request $request): ?\Illuminate\Http\JsonResponse
    {
        $admin = $this->authenticatedAdminFromToken($request);

        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $request->attributes->set('auth_admin', $admin);

        return null;
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

    private function logEmployeeAction(Request $request, Employee $employee, string $action, string $actionText): void
    {
        /** @var Admin|null $admin */
        $admin = $request->attributes->get('auth_admin');
        $adminId = $admin?->id;
        $adminName = $admin?->full_name ?: 'unknown admin';
        $employeeName = $employee->emp_name ?: 'unknown employee';

        $log = new Log();
        $log->admin_id = $adminId;
        $log->employee_id = $employee->id;
        $log->model = class_basename($employee);
        $log->action = $action;
        $log->description = sprintf(
            'admin(%s) %s employee(%s)',
            $adminName,
            $actionText,
            $employeeName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logEmployeeDeleteAction(Request $request, ?int $employeeId, string $employeeName): void
    {
        /** @var Admin|null $admin */
        $admin = $request->attributes->get('auth_admin');
        $adminId = $admin?->id;
        $adminName = $admin?->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $adminId;
        $log->employee_id = $employeeId;
        $log->model = class_basename(Employee::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) deleted employee(%s)',
            $adminName,
            $employeeName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
