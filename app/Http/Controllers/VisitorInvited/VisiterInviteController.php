<?php

namespace App\Http\Controllers\VisitorInvited;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Log;
use App\Models\VisitorInvited;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class VisiterInviteController extends Controller
{
    public function index(Request $request)
    {
        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
        ]);

        $query = VisitorInvited::query();
        $search = trim((string) ($validated['search'] ?? ''));

        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('name', 'like', '%' . $search . '%')
                    ->orWhere('email', 'like', '%' . $search . '%')
                    ->orWhere('phone', 'like', '%' . $search . '%')
                    ->orWhere('contact_person_name', 'like', '%' . $search . '%')
                    ->orWhere('contact_person_phone', 'like', '%' . $search . '%')
                    ->orWhere('purpose', 'like', '%' . $search . '%')
                    ->orWhere('invite_code', 'like', '%' . $search . '%');
            });
        }

        $visitors = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Visitor invites fetched successfully.',
            'data' => $visitors->items(),
            'pagination' => [
                'current_page' => $visitors->currentPage(),
                'last_page' => $visitors->lastPage(),
                'per_page' => $visitors->perPage(),
                'total' => $visitors->total(),
            ],
        ]);
    }

    public function store(Request $request)
    {
        $admin = $this->authenticatedAdminFromToken($request);

        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:visitor_inviteds,email'],
            'phone' => ['nullable', 'string', 'max:30'],
            'contact_person_name' => ['nullable', 'string', 'max:255'],
            'contact_person_phone' => ['nullable', 'string', 'max:30'],
            'purpose' => ['nullable', 'string', 'max:255'],
            'visit_date' => ['nullable', 'date'],
            'invite_code' => ['nullable', 'string', 'max:255', 'unique:visitor_inviteds,invite_code'],
        ]);

        $visitor = new VisitorInvited();
        $visitor->name = $validated['name'];
        $visitor->email = $validated['email'];
        $visitor->phone = $validated['phone'] ?? null;
        $visitor->contact_person_name = $validated['contact_person_name'] ?? null;
        $visitor->contact_person_phone = $validated['contact_person_phone'] ?? null;
        $visitor->purpose = $validated['purpose'] ?? null;
        $visitor->visit_date = $validated['visit_date'] ?? null;
        $visitor->invite_code = $validated['invite_code'] ?? $this->generateInviteCode();
        $visitor->save();
        $this->logVisitorAction($request, $admin, $visitor, 'create', 'created visitor invite');

        return response()->json([
            'status' => true,
            'message' => 'Visitor invite created successfully.',
            'data' => $visitor,
        ], 201);
    }

    public function show(int $id)
    {
        $visitor = VisitorInvited::find($id);

        if (!$visitor) {
            return response()->json([
                'status' => false,
                'message' => 'Visitor invite not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Visitor invite fetched successfully.',
            'data' => $visitor,
        ]);
    }

    public function update(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);

        $visitor = VisitorInvited::find($id);

        if (!$visitor) {
            return response()->json([
                'status' => false,
                'message' => 'Visitor invite not found.',
            ], 404);
        }

        $validated = $request->validate([
            'name' => ['sometimes', 'required', 'string', 'max:255'],
            'email' => ['sometimes', 'required', 'email', 'max:255', Rule::unique('visitor_inviteds', 'email')->ignore($visitor->id)],
            'phone' => ['nullable', 'string', 'max:30'],
            'contact_person_name' => ['nullable', 'string', 'max:255'],
            'contact_person_phone' => ['nullable', 'string', 'max:30'],
            'purpose' => ['nullable', 'string', 'max:255'],
            'visit_date' => ['nullable', 'date'],
            'invite_code' => ['sometimes', 'required', 'string', 'max:255', Rule::unique('visitor_inviteds', 'invite_code')->ignore($visitor->id)],
        ]);

        if (array_key_exists('name', $validated)) {
            $visitor->name = $validated['name'];
        }
        if (array_key_exists('email', $validated)) {
            $visitor->email = $validated['email'];
        }
        if (array_key_exists('phone', $validated)) {
            $visitor->phone = $validated['phone'];
        }
        if (array_key_exists('contact_person_name', $validated)) {
            $visitor->contact_person_name = $validated['contact_person_name'];
        }
        if (array_key_exists('contact_person_phone', $validated)) {
            $visitor->contact_person_phone = $validated['contact_person_phone'];
        }
        if (array_key_exists('purpose', $validated)) {
            $visitor->purpose = $validated['purpose'];
        }
        if (array_key_exists('visit_date', $validated)) {
            $visitor->visit_date = $validated['visit_date'];
        }
        if (array_key_exists('invite_code', $validated)) {
            $visitor->invite_code = $validated['invite_code'];
        }

        $visitor->save();
        $this->logVisitorAction($request, $admin, $visitor, 'update', 'updated visitor invite');

        return response()->json([
            'status' => true,
            'message' => 'Visitor invite updated successfully.',
            'data' => $visitor,
        ]);
    }

    public function destroy(Request $request, int $id)
    {
        $admin = $this->authenticatedAdminFromToken($request);

        $visitor = VisitorInvited::find($id);

        if (!$visitor) {
            return response()->json([
                'status' => false,
                'message' => 'Visitor invite not found.',
            ], 404);
        }

        $visitorName = $visitor->name ?: 'unknown visitor';
        $visitor->delete();
        $this->logVisitorDeleteAction($request, $admin, $visitorName);

        return response()->json([
            'status' => true,
            'message' => 'Visitor invite deleted successfully.',
        ]);
    }

    private function generateInviteCode(): string
    {
        do {
            $code = strtoupper(Str::random(8));
        } while (VisitorInvited::where('invite_code', $code)->exists());

        return $code;
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

    private function logVisitorAction(
        Request $request,
        ?Admin $admin,
        VisitorInvited $visitor,
        string $action,
        string $actionText
    ): void {
        $adminName = $admin?->full_name ?: 'unknown admin';
        $visitorName = $visitor->name ?: 'unknown visitor';

        $log = new Log();
        $log->admin_id = $admin?->id;
        $log->employee_id = null;
        $log->model = class_basename($visitor);
        $log->action = $action;
        $log->description = sprintf(
            'admin(%s) %s (%s)',
            $adminName,
            $actionText,
            $visitorName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logVisitorDeleteAction(Request $request, ?Admin $admin, string $visitorName): void
    {
        $adminName = $admin?->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $admin?->id;
        $log->employee_id = null;
        $log->model = class_basename(VisitorInvited::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) deleted visitor invite (%s)',
            $adminName,
            $visitorName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
