<?php

namespace App\Http\Controllers\Leads;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Lead;
use App\Models\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Validation\Rule;

class LeadController extends Controller
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
            'admin_id' => ['nullable', 'integer', 'exists:admins,id'],
            'search' => ['nullable', 'string', 'max:255'],
        ]);

        $query = Lead::query();
        if (!empty($validated['admin_id'])) {
            $query->where('admin_id', (int) $validated['admin_id']);
        }

        $search = trim((string) ($validated['search'] ?? ''));

        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('name', 'like', '%' . $search . '%')
                    ->orWhere('email', 'like', '%' . $search . '%')
                    ->orWhere('phone', 'like', '%' . $search . '%')
                    ->orWhere('company_name', 'like', '%' . $search . '%')
                    ->orWhere('status', 'like', '%' . $search . '%')
                    ->orWhere('source', 'like', '%' . $search . '%')
                    ->orWhere('priority', 'like', '%' . $search . '%');
            });
        }

        $leads = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Leads fetched successfully.',
            'data' => $leads->items(),
            'pagination' => [
                'current_page' => $leads->currentPage(),
                'last_page' => $leads->lastPage(),
                'per_page' => $leads->perPage(),
                'total' => $leads->total(),
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
            'admin_id' => ['required', 'integer', 'exists:admins,id'],
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:leads,email'],
            'phone' => ['nullable', 'string', 'max:30'],
            'company_name' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'string', 'max:100'],
            'source' => ['required', 'string', 'max:255'],
            'priority' => ['required', 'string', 'max:100'],
        ]);

        $lead = new Lead();
        $lead->admin_id = (int) $validated['admin_id'];
        $lead->name = $validated['name'];
        $lead->email = $validated['email'];
        $lead->phone = $validated['phone'] ?? null;
        $lead->company_name = $validated['company_name'] ?? null;
        $lead->status = $validated['status'] ?? 'open';
        $lead->source = $validated['source'];
        $lead->priority = $validated['priority'];
        $lead->save();
        $this->logLeadAction($request, $admin, $lead, 'create', 'created lead');

        return response()->json([
            'status' => true,
            'message' => 'Lead created successfully.',
            'data' => $lead,
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

        $lead = Lead::find($id);
        if (!$lead) {
            return response()->json([
                'status' => false,
                'message' => 'Lead not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Lead fetched successfully.',
            'data' => $lead,
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

        $lead = Lead::find($id);
        if (!$lead) {
            return response()->json([
                'status' => false,
                'message' => 'Lead not found.',
            ], 404);
        }

        $validated = $request->validate([
            'admin_id' => ['sometimes', 'required', 'integer', 'exists:admins,id'],
            'name' => ['sometimes', 'required', 'string', 'max:255'],
            'email' => ['sometimes', 'required', 'email', 'max:255', Rule::unique('leads', 'email')->ignore($lead->id)],
            'phone' => ['nullable', 'string', 'max:30'],
            'company_name' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'string', 'max:100'],
            'source' => ['sometimes', 'required', 'string', 'max:255'],
            'priority' => ['sometimes', 'required', 'string', 'max:100'],
        ]);

        if (array_key_exists('admin_id', $validated)) {
            $lead->admin_id = (int) $validated['admin_id'];
        }
        if (array_key_exists('name', $validated)) {
            $lead->name = $validated['name'];
        }
        if (array_key_exists('email', $validated)) {
            $lead->email = $validated['email'];
        }
        if (array_key_exists('phone', $validated)) {
            $lead->phone = $validated['phone'];
        }
        if (array_key_exists('company_name', $validated)) {
            $lead->company_name = $validated['company_name'];
        }
        if (array_key_exists('status', $validated)) {
            $lead->status = $validated['status'];
        }
        if (array_key_exists('source', $validated)) {
            $lead->source = $validated['source'];
        }
        if (array_key_exists('priority', $validated)) {
            $lead->priority = $validated['priority'];
        }

        $lead->save();
        $this->logLeadAction($request, $admin, $lead, 'update', 'updated lead');

        return response()->json([
            'status' => true,
            'message' => 'Lead updated successfully.',
            'data' => $lead,
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

        $lead = Lead::find($id);
        if (!$lead) {
            return response()->json([
                'status' => false,
                'message' => 'Lead not found.',
            ], 404);
        }

        $leadName = $lead->name ?: 'unknown lead';
        $lead->delete();
        $this->logLeadDeleteAction($request, $admin, $leadName);

        return response()->json([
            'status' => true,
            'message' => 'Lead deleted successfully.',
        ]);
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

    private function logLeadAction(
        Request $request,
        Admin $admin,
        Lead $lead,
        string $action,
        string $actionText
    ): void {
        $adminName = $admin->full_name ?: 'unknown admin';
        $leadName = $lead->name ?: 'unknown lead';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = null;
        $log->model = class_basename($lead);
        $log->action = $action;
        $log->description = sprintf(
            'admin(%s) %s (%s)',
            $adminName,
            $actionText,
            $leadName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logLeadDeleteAction(Request $request, Admin $admin, string $leadName): void
    {
        $adminName = $admin->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = null;
        $log->model = class_basename(Lead::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) deleted lead (%s)',
            $adminName,
            $leadName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }
}
