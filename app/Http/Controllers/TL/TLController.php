<?php

namespace App\Http\Controllers\TL;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Employee;
use App\Models\EmployeeFamilyDetails;
use App\Models\EmployeeDocuments;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class TLController extends Controller
{
    public function index(Request $request)
    {
        if ($authResponse = $this->ensureAdminAuthorized($request)) {
            return $authResponse;
        }

        $tls = Employee::with([
            'familyDetails',
            'bankDetails',
            'payrolls',
            'qualifications',
            'addresses',
            'documents',
            'experiences',
        ])
        ->whereIn('role', ['TL', 'tl', 'Team Lead'])
        ->latest()
        ->get();

        return response()->json([
            'status' => true,
            'message' => 'Team Leads fetched successfully.',
            'data' => $tls->map(fn(Employee $employee) => $this->transformEmployee($employee)),
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

        return $data;
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
        if (!in_array($payload['role'] ?? null, ['admin', 'subadmin', 'sub_admin'])) {
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
