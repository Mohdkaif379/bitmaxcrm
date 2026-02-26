<?php

namespace App\Http\Controllers\SubAdmin;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\Rule;

class SubAdminController extends Controller
{
    private const SUB_ADMIN_ROLE = 'sub_admin';

    public function index(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid admin token is required.',
            ], 401);
        }

        $subAdmins = Admin::query()
            ->whereIn('role', [self::SUB_ADMIN_ROLE, 'subadmin'])
            ->latest()
            ->get();

        return response()->json([
            'status' => true,
            'message' => 'Sub admins fetched successfully.',
            'data' => $subAdmins->map(fn (Admin $subAdmin) => $this->transformSubAdmin($subAdmin)),
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
            'full_name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:admins,email'],
            'password' => ['required', 'string', 'min:6'],
            'number' => ['nullable', 'string', 'max:20'],
            'profile_photo' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:2048'],
            'permissions' => ['nullable', 'array'],
            'permissions.*' => ['required'],
            'status' => ['nullable', 'boolean'],
            'bio' => ['nullable', 'string'],
        ]);

        $profilePhotoPath = null;
        if ($request->hasFile('profile_photo')) {
            $profilePhotoPath = $request->file('profile_photo')->store('admins/profile_photos', 'public');
        }

        $subAdmin = new Admin();
        $subAdmin->full_name = $validated['full_name'];
        $subAdmin->email = $validated['email'];
        $subAdmin->password = Hash::make($validated['password']);
        $subAdmin->number = $validated['number'] ?? null;
        $subAdmin->profile_photo = $profilePhotoPath;
        $subAdmin->role = self::SUB_ADMIN_ROLE;
        $subAdmin->permissions = $this->normalizeModulePermissions($validated['permissions'] ?? []);
        $subAdmin->status = $validated['status'] ?? true;
        $subAdmin->bio = $validated['bio'] ?? null;
        $subAdmin->save();
        $this->logSubAdminAction($request, $admin, $subAdmin, 'create', 'created sub admin');

        return response()->json([
            'status' => true,
            'message' => 'Sub admin created successfully.',
            'data' => $this->transformSubAdmin($subAdmin),
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

        $subAdmin = $this->findSubAdmin($id);
        if (!$subAdmin) {
            return response()->json([
                'status' => false,
                'message' => 'Sub admin not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Sub admin fetched successfully.',
            'data' => $this->transformSubAdmin($subAdmin),
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

        $subAdmin = $this->findSubAdmin($id);
        if (!$subAdmin) {
            return response()->json([
                'status' => false,
                'message' => 'Sub admin not found.',
            ], 404);
        }

        $validated = $request->validate([
            'full_name' => ['sometimes', 'required', 'string', 'max:255'],
            'email' => [
                'sometimes',
                'required',
                'email',
                'max:255',
                Rule::unique('admins', 'email')->ignore($subAdmin->id),
            ],
            'password' => ['sometimes', 'required', 'string', 'min:6'],
            'number' => ['nullable', 'string', 'max:20'],
            'profile_photo' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:2048'],
            'permissions' => ['nullable', 'array'],
            'permissions.*' => ['required'],
            'status' => ['nullable', 'boolean'],
            'bio' => ['nullable', 'string'],
        ]);

        if (array_key_exists('full_name', $validated)) {
            $subAdmin->full_name = $validated['full_name'];
        }
        if (array_key_exists('email', $validated)) {
            $subAdmin->email = $validated['email'];
        }
        if (array_key_exists('password', $validated)) {
            $subAdmin->password = Hash::make($validated['password']);
        }
        if (array_key_exists('number', $validated)) {
            $subAdmin->number = $validated['number'];
        }
        if (array_key_exists('permissions', $validated)) {
            $subAdmin->permissions = $this->normalizeModulePermissions($validated['permissions'] ?? []);
        }
        if (array_key_exists('status', $validated)) {
            $subAdmin->status = $validated['status'];
        }
        if (array_key_exists('bio', $validated)) {
            $subAdmin->bio = $validated['bio'];
        }

        if ($request->hasFile('profile_photo')) {
            if ($subAdmin->profile_photo && Storage::disk('public')->exists($subAdmin->profile_photo)) {
                Storage::disk('public')->delete($subAdmin->profile_photo);
            }
            $subAdmin->profile_photo = $request->file('profile_photo')->store('admins/profile_photos', 'public');
        }

        $subAdmin->role = self::SUB_ADMIN_ROLE;
        $subAdmin->save();
        $this->logSubAdminAction($request, $admin, $subAdmin, 'update', 'updated sub admin');

        return response()->json([
            'status' => true,
            'message' => 'Sub admin updated successfully.',
            'data' => $this->transformSubAdmin($subAdmin),
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

        $subAdmin = $this->findSubAdmin($id);
        if (!$subAdmin) {
            return response()->json([
                'status' => false,
                'message' => 'Sub admin not found.',
            ], 404);
        }

        if ($subAdmin->profile_photo && Storage::disk('public')->exists($subAdmin->profile_photo)) {
            Storage::disk('public')->delete($subAdmin->profile_photo);
        }

        $subAdminName = $subAdmin->full_name ?: 'unknown sub admin';
        $subAdmin->delete();
        $this->logSubAdminDeleteAction($request, $admin, $subAdminName);

        return response()->json([
            'status' => true,
            'message' => 'Sub admin deleted successfully.',
        ]);
    }

    private function findSubAdmin(int $id): ?Admin
    {
        return Admin::query()
            ->where('id', $id)
            ->whereIn('role', [self::SUB_ADMIN_ROLE, 'subadmin'])
            ->first();
    }

    private function transformSubAdmin(Admin $subAdmin): array
    {
        $data = $subAdmin->toArray();
        unset($data['password']);
        $data['profile_photo'] = $subAdmin->profile_photo ? url(Storage::url($subAdmin->profile_photo)) : null;
        $data['accessible_modules'] = $this->accessibleModules($data['permissions'] ?? []);
        $data['accessible_modules_count'] = count($data['accessible_modules']);
        $data['total_modules_count'] = is_array($data['permissions'] ?? null) ? count($data['permissions']) : 0;

        return $data;
    }

    private function normalizeModulePermissions(array $permissions): array
    {
        $normalized = [];

        foreach ($permissions as $module => $value) {
            if (is_int($module)) {
                continue;
            }

            $moduleKey = trim(strtolower((string) $module));
            if ($moduleKey === '') {
                continue;
            }

            $normalized[$moduleKey] = $this->toYesNo($value);
        }

        return $normalized;
    }

    private function accessibleModules(array $permissions): array
    {
        $accessible = [];

        foreach ($permissions as $module => $value) {
            if (strtolower((string) $value) === 'yes') {
                $accessible[] = (string) $module;
            }
        }

        return array_values($accessible);
    }

    private function toYesNo(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'yes' : 'no';
        }

        $normalized = strtolower(trim((string) $value));
        if (in_array($normalized, ['yes', '1', 'true'], true)) {
            return 'yes';
        }

        return 'no';
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

    private function logSubAdminAction(
        Request $request,
        Admin $actorAdmin,
        Admin $subAdmin,
        string $action,
        string $actionText
    ): void {
        $actorName = $actorAdmin->full_name ?: 'unknown admin';
        $subAdminName = $subAdmin->full_name ?: 'unknown sub admin';

        $log = new Log();
        $log->admin_id = $actorAdmin->id;
        $log->employee_id = null;
        $log->model = class_basename($subAdmin);
        $log->action = $action;
        $log->description = sprintf(
            'admin(%s) %s (%s)',
            $actorName,
            $actionText,
            $subAdminName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logSubAdminDeleteAction(
        Request $request,
        Admin $actorAdmin,
        string $subAdminName
    ): void {
        $actorName = $actorAdmin->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $actorAdmin->id;
        $log->employee_id = null;
        $log->model = class_basename(Admin::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) deleted sub admin (%s)',
            $actorName,
            $subAdminName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
