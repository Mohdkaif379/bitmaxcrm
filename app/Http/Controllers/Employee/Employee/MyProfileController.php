<?php

namespace App\Http\Controllers\Employee\Employee;

use App\Http\Controllers\Controller;
use App\Models\Employee;
use App\Models\EmployeeDocuments;
use App\Models\EmployeeFamilyDetails;
use App\Models\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;

class MyProfileController extends Controller
{
    public function show(Request $request)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        $employee->load([
            'familyDetails',
            'bankDetails',
            'payrolls',
            'qualifications',
            'addresses',
            'documents',
            'experiences',
            'tasks',
        ]);
        $this->logEmployeeProfileAction($request, $employee, 'view', 'viewed profile');

        return response()->json([
            'status' => true,
            'message' => 'My profile fetched successfully.',
            'data' => $this->transformEmployee($employee),
        ]);
    }

    public function updateMyProfile(Request $request)
    {
        $employee = $this->authenticatedEmployeeFromToken($request);
        if (!$employee) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid employee token is required.',
            ], 401);
        }

        // Accept common aliases from clients/postman payloads.
        if ($request->filled('name') && !$request->has('emp_name')) {
            $request->merge(['emp_name' => $request->input('name')]);
        }

        if ($request->filled('confirm_password') && !$request->has('password_confirmation')) {
            $request->merge(['password_confirmation' => $request->input('confirm_password')]);
        }

        if ($request->hasFile('profile_image') && !$request->hasFile('profile_photo')) {
            $request->files->set('profile_photo', $request->file('profile_image'));
        }

        $hasDocuments   = $request->has('documents') && is_array($request->input('documents'));
        $hasDeleteDocs  = $request->has('delete_document_ids') && is_array($request->input('delete_document_ids'));

        if (
            !$request->has('emp_name')
            && !$request->has('password')
            && !$request->hasFile('profile_photo')
            && !$hasDocuments
            && !$hasDeleteDocs
        ) {
            return response()->json([
                'status' => false,
                'message' => 'At least one field is required: emp_name, password, profile_photo, documents, or delete_document_ids.',
            ], 422);
        }

        $validated = $request->validate([
            'emp_name'                    => ['sometimes', 'required', 'string', 'max:255'],
            'password'                    => ['sometimes', 'required', 'string', 'min:6', 'confirmed'],
            'profile_photo'               => ['sometimes', 'required', 'image', 'mimes:jpg,jpeg,png,webp', 'max:2048'],
            'documents'                   => ['sometimes', 'array'],
            'documents.*.id'              => ['sometimes', 'nullable', 'integer', 'exists:employee_documents,id'],
            'documents.*.document_type'   => ['required_with:documents', 'string', 'max:255'],
            'documents.*.file'            => ['sometimes', 'nullable', 'file', 'mimes:jpg,jpeg,png,pdf,webp', 'max:5120'],
            'delete_document_ids'         => ['sometimes', 'array'],
            'delete_document_ids.*'       => ['integer', 'exists:employee_documents,id'],
        ]);

        if (array_key_exists('emp_name', $validated)) {
            $employee->emp_name = $validated['emp_name'];
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

        // ── Delete documents ───────────────────────────────────────────────────
        if ($hasDeleteDocs) {
            $docsToDelete = EmployeeDocuments::where('employee_id', $employee->id)
                ->whereIn('id', $request->input('delete_document_ids'))
                ->get();

            foreach ($docsToDelete as $doc) {
                if ($doc->file && Storage::disk('public')->exists($doc->file)) {
                    Storage::disk('public')->delete($doc->file);
                }
                $doc->delete();
            }
        }

        // ── Add / update documents ─────────────────────────────────────────────
        if ($hasDocuments) {
            foreach ($request->input('documents') as $index => $docData) {
                $docId   = $docData['id'] ?? null;
                $docType = $docData['document_type'] ?? null;
                $uploadedFile = $request->file("documents.{$index}.file") ?? null;

                if ($docId) {
                    // Update existing document (must belong to this employee)
                    $doc = EmployeeDocuments::where('id', $docId)
                        ->where('employee_id', $employee->id)
                        ->first();

                    if ($doc) {
                        if ($docType) {
                            $doc->document_type = $docType;
                        }
                        if ($uploadedFile) {
                            // Delete old file
                            if ($doc->file && Storage::disk('public')->exists($doc->file)) {
                                Storage::disk('public')->delete($doc->file);
                            }
                            $doc->file = $uploadedFile->store('employees/documents', 'public');
                        }
                        $doc->save();
                    }
                } else {
                    // Create new document
                    if ($docType && $uploadedFile) {
                        EmployeeDocuments::create([
                            'employee_id'   => $employee->id,
                            'document_type' => $docType,
                            'file'          => $uploadedFile->store('employees/documents', 'public'),
                        ]);
                    }
                }
            }
        }

        $employee->load([
            'familyDetails',
            'bankDetails',
            'payrolls',
            'qualifications',
            'addresses',
            'documents',
            'experiences',
            'tasks',
        ]);
        $this->logEmployeeProfileAction($request, $employee, 'update', 'updated profile');

        return response()->json([
            'status' => true,
            'message' => 'My profile updated successfully.',
            'data' => $this->transformEmployee($employee),
        ]);
    }

    private function transformEmployee(Employee $employee): array
    {
        $data = $employee->toArray();
        unset($data['password']);
        $data['profile_photo'] = $employee->profile_photo ? url('public/storage/' . $employee->profile_photo) : null;

        $data['family_details'] = $employee->familyDetails->map(function (EmployeeFamilyDetails $item) {
            return [
                'id' => $item->id,
                'employee_id' => $item->employee_id,
                'name' => $item->name,
                'relationship' => $item->relationship,
                'contact' => $item->contact,
                'aadhar_number' => $item->aadhar_number,
                'aadhar_profile' => $item->aadhar_profile ? url('public/storage/' . $item->aadhar_profile) : null,
                'pan_number' => $item->pan_number,
                'pan_profile' => $item->pan_profile ? url('public/storage/' . $item->pan_profile) : null,
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
                'file' => $item->file ? url('public/storage/' . $item->file) : null,
                'created_at' => $item->created_at,
                'updated_at' => $item->updated_at,
            ];
        })->values();

        $data['experiences'] = $employee->experiences->values();
        $data['tasks'] = $employee->tasks->values();

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

    private function logEmployeeProfileAction(Request $request, Employee $employee, string $action, string $actionText): void
    {
        $employeeName = $employee->emp_name ?: 'unknown employee';

        $log = new Log();
        $log->admin_id = null;
        $log->employee_id = $employee->id;
        $log->model = class_basename(Employee::class);
        $log->action = $action;
        $log->description = sprintf(
            'employee(%s) %s',
            $employeeName,
            $actionText
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
