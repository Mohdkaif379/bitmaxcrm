<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\LoginHistory;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class AdminController extends Controller
{
    public function login(Request $request)
    {
        $validated = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        $admin = Admin::where('email', $validated['email'])->first();

        if (!$admin || !Hash::check($validated['password'], $admin->password)) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid email or password.',
            ], 401);
        }

        $currentCount = (int) optional(
            LoginHistory::where('admin_id', $admin->id)->latest('id')->first()
        )->profile_updated;

        $loginHistory = new LoginHistory();
        $loginHistory->admin_id = $admin->id;
        $loginHistory->login_time = now('Asia/Kolkata');
        $loginHistory->ip_address = $request->ip();
        $loginHistory->profile_updated = (string) $currentCount;
        $loginHistory->save();

        $token = $this->createJwtToken($admin, $loginHistory->id);

        return response()->json([
            'status' => true,
            'message' => 'Login successful.',
            'token_type' => 'Bearer',
            'access_token' => $token,
            'expires_in' => null,
            'data' => $this->transformAdmin($admin),
        ]);
    }

    public function logout(Request $request)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json([
                'status' => false,
                'message' => 'Bearer token is required.',
            ], 400);
        }

        $payload = $this->decodeJwtToken($token);

        if (!$payload) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid or expired token.',
            ], 401);
        }

        $blacklistKey = 'admin_jwt_blacklist:' . hash('sha256', $token);
        Cache::forever($blacklistKey, true);

        if (isset($payload['lhid'])) {
            $loginHistory = LoginHistory::where('id', (int) $payload['lhid'])
                ->where('admin_id', (int) ($payload['sub'] ?? 0))
                ->first();

            if ($loginHistory) {
                $loginHistory->logout_time = now('Asia/Kolkata');
                $loginHistory->save();
            }
        }

        return response()->json([
            'status' => true,
            'message' => 'Logout successful.',
        ]);
    }

    public function index()
    {
        $admins = Admin::latest()->get();

        return response()->json([
            'status' => true,
            'message' => 'Admins fetched successfully.',
            'data' => $admins->map(fn (Admin $admin) => $this->transformAdmin($admin)),
        ]);
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'full_name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:admins,email'],
            'password' => ['required', 'string', 'min:6'],
            'number' => ['nullable', 'string', 'max:20'],
            'profile_photo' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:2048'],
            'role' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'boolean'],
            'bio' => ['nullable', 'string'],
            'company_logo' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:2048'],
            'company_name' => ['nullable', 'string', 'max:255'],
        ]);

        $profilePhotoPath = null;
        if ($request->hasFile('profile_photo')) {
            $profilePhotoPath = $request->file('profile_photo')->store('admins/profile_photos', 'public');
        }

        $companyLogoPath = null;
        if ($request->hasFile('company_logo')) {
            $companyLogoPath = $request->file('company_logo')->store('admins/company_logos', 'public');
        }

        $admin = new Admin();
        $admin->full_name = $validated['full_name'];
        $admin->email = $validated['email'];
        $admin->password = Hash::make($validated['password']);
        $admin->number = $validated['number'] ?? null;
        $admin->profile_photo = $profilePhotoPath;
        $admin->role = $validated['role'] ?? 'admin';
        $admin->status = $validated['status'] ?? true;
        $admin->bio = $validated['bio'] ?? null;
        $admin->company_logo = $companyLogoPath;
        $admin->company_name = $validated['company_name'] ?? null;
        $admin->save();

        return response()->json([
            'status' => true,
            'message' => 'Admin created successfully.',
            'data' => $this->transformAdmin($admin),
        ], 201);
    }

    public function show($id)
    {
        $admin = Admin::find($id);

        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Admin not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Admin fetched successfully.',
            'data' => $this->transformAdmin($admin),
        ]);
    }

    public function update(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized.',
            ], 401);
        }

        $validated = $request->validate([
            'full_name' => ['sometimes', 'required', 'string', 'max:255'],
            'email' => [
                'sometimes',
                'required',
                'email',
                'max:255',
                Rule::unique('admins', 'email')->ignore($admin->id),
            ],
            'password' => ['sometimes', 'required', 'string', 'min:6'],
            'number' => ['nullable', 'string', 'max:20'],
            'profile_photo' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:2048'],
            'role' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'boolean'],
            'bio' => ['nullable', 'string'],
            'company_logo' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:2048'],
            'company_name' => ['nullable', 'string', 'max:255'],
        ]);

        if (array_key_exists('full_name', $validated)) {
            $admin->full_name = $validated['full_name'];
        }

        if (array_key_exists('email', $validated)) {
            $admin->email = $validated['email'];
        }

        if (array_key_exists('password', $validated)) {
            $admin->password = Hash::make($validated['password']);
        }

        if (array_key_exists('number', $validated)) {
            $admin->number = $validated['number'];
        }

        if ($request->hasFile('profile_photo')) {
            if ($admin->profile_photo && Storage::disk('public')->exists($admin->profile_photo)) {
                Storage::disk('public')->delete($admin->profile_photo);
            }

            $admin->profile_photo = $request->file('profile_photo')->store('admins/profile_photos', 'public');
        }

        if (array_key_exists('role', $validated)) {
            $admin->role = $validated['role'];
        }

        if (array_key_exists('status', $validated)) {
            $admin->status = $validated['status'];
        }

        if (array_key_exists('bio', $validated)) {
            $admin->bio = $validated['bio'];
        }

        if ($request->hasFile('company_logo')) {
            if ($admin->company_logo && Storage::disk('public')->exists($admin->company_logo)) {
                Storage::disk('public')->delete($admin->company_logo);
            }

            $admin->company_logo = $request->file('company_logo')->store('admins/company_logos', 'public');
        }

        if (array_key_exists('company_name', $validated)) {
            $admin->company_name = $validated['company_name'];
        }

        $admin->save();
        $this->incrementProfileUpdateCount($admin->id);

        return response()->json([
            'status' => true,
            'message' => 'Admin updated successfully.',
            'data' => $this->transformAdmin($admin),
        ]);
    }

    public function destroy(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);
        if (!$admin) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized.',
            ], 401);
        }

        if ($admin->profile_photo && Storage::disk('public')->exists($admin->profile_photo)) {
            Storage::disk('public')->delete($admin->profile_photo);
        }

        if ($admin->company_logo && Storage::disk('public')->exists($admin->company_logo)) {
            Storage::disk('public')->delete($admin->company_logo);
        }

        $admin->delete();

        return response()->json([
            'status' => true,
            'message' => 'Admin deleted successfully.',
        ]);
    }

    private function transformAdmin(Admin $admin): array
    {
        $data = $admin->toArray();
        unset($data['password']);
        $data['profile_photo'] = $admin->profile_photo ? url(Storage::url($admin->profile_photo)) : null;
        $data['company_logo'] = $admin->company_logo ? url(Storage::url($admin->company_logo)) : null;

        return $data;
    }

    private function createJwtToken(Admin $admin, int $loginHistoryId): string
    {
        $now = time();

        $header = [
            'alg' => 'HS256',
            'typ' => 'JWT',
        ];

        $payload = [
            'iss' => config('app.url'),
            'sub' => (string) $admin->id,
            'email' => $admin->email,
            'role' => $admin->role,
            'lhid' => $loginHistoryId,
            'iat' => $now,
            'nbf' => $now,
            'jti' => (string) Str::uuid(),
        ];

        $encodedHeader = $this->base64UrlEncode(json_encode($header, JSON_UNESCAPED_SLASHES));
        $encodedPayload = $this->base64UrlEncode(json_encode($payload, JSON_UNESCAPED_SLASHES));
        $signature = hash_hmac('sha256', $encodedHeader . '.' . $encodedPayload, $this->jwtSecret(), true);
        $encodedSignature = $this->base64UrlEncode($signature);

        return $encodedHeader . '.' . $encodedPayload . '.' . $encodedSignature;
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

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): string|false
    {
        $remainder = strlen($value) % 4;
        if ($remainder) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($value, '-_', '+/'), true);
    }

    private function incrementProfileUpdateCount(int $adminId): void
    {
        $loginHistory = LoginHistory::where('admin_id', $adminId)->latest('id')->first();

        if (!$loginHistory) {
            $loginHistory = new LoginHistory();
            $loginHistory->admin_id = $adminId;
            $loginHistory->login_time = now('Asia/Kolkata');
            $loginHistory->ip_address = request()->ip();
            $loginHistory->profile_updated = '0';
        }

        $current = (int) $loginHistory->profile_updated;
        $loginHistory->profile_updated = (string) ($current + 1);
        $loginHistory->save();
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

        $adminId = (int) ($payload['sub'] ?? 0);
        if ($adminId <= 0) {
            return null;
        }

        return Admin::find($adminId);
    }
}
