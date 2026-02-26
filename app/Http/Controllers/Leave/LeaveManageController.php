<?php

namespace App\Http\Controllers\Leave;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\LeaveManagement;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

class LeaveManageController extends Controller
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
            'status' => ['nullable', 'in:pending,approved,rejected'],
        ]);

        $query = LeaveManagement::with(['employee', 'approvedBy'])->latest('id');

        if (!empty($validated['status'])) {
            $query->where('status', $validated['status']);
        }

        $leaves = $query->get();

        return response()->json([
            'status' => true,
            'message' => 'Leave requests fetched successfully.',
            'data' => $leaves->map(fn (LeaveManagement $leave) => $this->transformLeave($leave))->values(),
        ]);
    }

    public function approve(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'status' => ['required', 'in:approved,rejected'],
        ]);

        $leave = LeaveManagement::with(['employee', 'approvedBy'])->find($id);
        if (!$leave) {
            return response()->json([
                'status' => false,
                'message' => 'Leave request not found.',
            ], 404);
        }

        $leave->status = $validated['status'];
        $leave->approved_by = $admin->id;
        $leave->save();
        $leave->load(['employee', 'approvedBy']);

        return response()->json([
            'status' => true,
            'message' => 'Leave request updated successfully.',
            'data' => $this->transformLeave($leave),
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

        $leave = LeaveManagement::with(['employee', 'approvedBy'])->find($id);
        if (!$leave) {
            return response()->json([
                'status' => false,
                'message' => 'Leave request not found.',
            ], 404);
        }

        $validated = $request->validate([
            'employee_id' => ['sometimes', 'required', 'integer', 'exists:employees,id'],
            'start_date' => ['sometimes', 'required', 'date'],
            'end_date' => ['sometimes', 'required', 'date', 'after_or_equal:start_date'],
            'subject' => ['sometimes', 'required', 'string', 'max:255'],
            'description' => ['sometimes', 'required', 'string'],
            'leave_type' => ['sometimes', 'required', 'string', 'max:255'],
            'status' => ['sometimes', 'required', 'in:pending,approved,rejected'],
            'file' => ['sometimes', 'nullable', 'file', 'mimes:jpg,jpeg,png,pdf,doc,docx,webp', 'max:5120'],
        ]);

        if (array_key_exists('employee_id', $validated)) {
            $leave->employee_id = (int) $validated['employee_id'];
        }
        if (array_key_exists('start_date', $validated)) {
            $leave->start_date = $validated['start_date'];
        }
        if (array_key_exists('end_date', $validated)) {
            $leave->end_date = $validated['end_date'];
        }
        if (array_key_exists('subject', $validated)) {
            $leave->subject = $validated['subject'];
        }
        if (array_key_exists('description', $validated)) {
            $leave->description = $validated['description'];
        }
        if (array_key_exists('leave_type', $validated)) {
            $leave->leave_type = $validated['leave_type'];
        }

        if (array_key_exists('status', $validated)) {
            $leave->status = $validated['status'];
            $leave->approved_by = in_array($validated['status'], ['approved', 'rejected'], true) ? $admin->id : null;
        }

        if ($request->hasFile('file')) {
            if ($leave->file && Storage::disk('public')->exists($leave->file)) {
                Storage::disk('public')->delete($leave->file);
            }
            $leave->file = $request->file('file')->store('leave-management/files', 'public');
        }

        $leave->total_days = Carbon::parse($leave->start_date)->diffInDays(Carbon::parse($leave->end_date)) + 1;
        $leave->save();
        $leave->load(['employee', 'approvedBy']);

        return response()->json([
            'status' => true,
            'message' => 'Leave request edited successfully.',
            'data' => $this->transformLeave($leave),
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

        $leave = LeaveManagement::find($id);
        if (!$leave) {
            return response()->json([
                'status' => false,
                'message' => 'Leave request not found.',
            ], 404);
        }

        if ($leave->file) {
            $pathToDelete = $leave->file;
            if (Storage::disk('public')->exists($pathToDelete)) {
                Storage::disk('public')->delete($pathToDelete);
            }
        }

        $leave->delete();

        return response()->json([
            'status' => true,
            'message' => 'Leave request deleted successfully.',
        ]);
    }

    private function transformLeave(LeaveManagement $leave): array
    {
        $data = $leave->toArray();
        $data['file'] = $leave->file ? url(Storage::url($leave->file)) : null;

        if ($leave->employee) {
            $employeeData = $leave->employee->toArray();
            unset($employeeData['password']);
            $employeeData['profile_photo'] = $leave->employee->profile_photo
                ? url(Storage::url($leave->employee->profile_photo))
                : null;
            $data['employee'] = $employeeData;
        } else {
            $data['employee'] = null;
        }

        if ($leave->approvedBy) {
            $approvedByAdmin = $leave->approvedBy->toArray();
            unset($approvedByAdmin['password']);
            $data['approved_by_admin'] = $approvedByAdmin;
        } else {
            $data['approved_by_admin'] = null;
        }

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
