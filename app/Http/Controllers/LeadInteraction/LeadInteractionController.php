<?php

namespace App\Http\Controllers\LeadInteraction;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Lead;
use App\Models\LeadInteraction;
use App\Models\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class LeadInteractionController extends Controller
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
            'lead_id' => ['nullable', 'integer', 'exists:leads,id'],
            'search' => ['nullable', 'string', 'max:255'],
            'interaction_type' => ['nullable', 'string', 'max:100'],
            'interaction_status' => ['nullable', 'string', 'max:100'],
            'interaction_date' => ['nullable', 'date'],
        ]);

        $query = LeadInteraction::query();

        if (!empty($validated['lead_id'])) {
            $query->where('lead_id', (int) $validated['lead_id']);
        }

        if (!empty($validated['interaction_type'])) {
            $query->where('interaction_type', $validated['interaction_type']);
        }

        if (!empty($validated['interaction_status'])) {
            $query->where('interaction_status', $validated['interaction_status']);
        }

        if (!empty($validated['interaction_date'])) {
            $query->whereDate('interaction_date', $validated['interaction_date']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('interaction_type', 'like', '%' . $search . '%')
                    ->orWhere('interaction_status', 'like', '%' . $search . '%')
                    ->orWhere('description', 'like', '%' . $search . '%');
            });
        }

        $interactions = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Lead interactions fetched successfully.',
            'data' => $interactions->items(),
            'pagination' => [
                'current_page' => $interactions->currentPage(),
                'last_page' => $interactions->lastPage(),
                'per_page' => $interactions->perPage(),
                'total' => $interactions->total(),
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
            'lead_id' => ['required', 'integer', 'exists:leads,id'],
            'interaction_type' => ['required', 'string', 'max:100'],
            'description' => ['nullable', 'string'],
            'interaction_date' => ['required', 'date'],
            'interaction_status' => ['nullable', 'string', 'max:100'],
            'next_follow_up_date' => ['nullable', 'date', 'after_or_equal:interaction_date'],
        ]);

        $interaction = new LeadInteraction();
        $interaction->lead_id = (int) $validated['lead_id'];
        $interaction->interaction_type = $validated['interaction_type'];
        $interaction->description = $validated['description'] ?? null;
        $interaction->interaction_date = $validated['interaction_date'];
        $interaction->interaction_status = $validated['interaction_status'] ?? 'pending';
        $interaction->next_follow_up_date = $validated['next_follow_up_date'] ?? null;
        $interaction->created_by = $admin->id;
        $interaction->save();
        $this->logLeadInteractionAction($request, $admin, $interaction, 'create', 'created lead interaction for');

        return response()->json([
            'status' => true,
            'message' => 'Lead interaction created successfully.',
            'data' => $interaction,
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

        $interaction = LeadInteraction::find($id);
        if (!$interaction) {
            return response()->json([
                'status' => false,
                'message' => 'Lead interaction not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Lead interaction fetched successfully.',
            'data' => $interaction,
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

        $interaction = LeadInteraction::find($id);
        if (!$interaction) {
            return response()->json([
                'status' => false,
                'message' => 'Lead interaction not found.',
            ], 404);
        }

        $validated = $request->validate([
            'lead_id' => ['sometimes', 'required', 'integer', 'exists:leads,id'],
            'interaction_type' => ['sometimes', 'required', 'string', 'max:100'],
            'description' => ['nullable', 'string'],
            'interaction_date' => ['sometimes', 'required', 'date'],
            'interaction_status' => ['nullable', 'string', 'max:100'],
            'next_follow_up_date' => ['nullable', 'date'],
        ]);

        if (array_key_exists('next_follow_up_date', $validated) && !empty($validated['next_follow_up_date'])) {
            $interactionDate = (string) ($validated['interaction_date'] ?? $interaction->interaction_date);

            if ($validated['next_follow_up_date'] < $interactionDate) {
                return response()->json([
                    'status' => false,
                    'message' => 'Next follow up date must be after or equal to interaction date.',
                ], 422);
            }
        }

        if (array_key_exists('lead_id', $validated)) {
            $interaction->lead_id = (int) $validated['lead_id'];
        }
        if (array_key_exists('interaction_type', $validated)) {
            $interaction->interaction_type = $validated['interaction_type'];
        }
        if (array_key_exists('description', $validated)) {
            $interaction->description = $validated['description'];
        }
        if (array_key_exists('interaction_date', $validated)) {
            $interaction->interaction_date = $validated['interaction_date'];
        }
        if (array_key_exists('interaction_status', $validated)) {
            $interaction->interaction_status = $validated['interaction_status'] ?: 'pending';
        }
        if (array_key_exists('next_follow_up_date', $validated)) {
            $interaction->next_follow_up_date = $validated['next_follow_up_date'];
        }

        $interaction->save();
        $this->logLeadInteractionAction($request, $admin, $interaction, 'update', 'updated lead interaction for');

        return response()->json([
            'status' => true,
            'message' => 'Lead interaction updated successfully.',
            'data' => $interaction,
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

        $interaction = LeadInteraction::find($id);
        if (!$interaction) {
            return response()->json([
                'status' => false,
                'message' => 'Lead interaction not found.',
            ], 404);
        }

        $leadName = $this->resolveLeadName($interaction->lead_id);
        $interaction->delete();
        $this->logLeadInteractionDeleteAction($request, $admin, $leadName);

        return response()->json([
            'status' => true,
            'message' => 'Lead interaction deleted successfully.',
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

    private function logLeadInteractionAction(
        Request $request,
        Admin $admin,
        LeadInteraction $interaction,
        string $action,
        string $actionText
    ): void {
        $adminName = $admin->full_name ?: 'unknown admin';
        $leadName = $this->resolveLeadName($interaction->lead_id);

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = null;
        $log->model = class_basename($interaction);
        $log->action = $action;
        $log->description = sprintf(
            'admin(%s) %s lead(%s)',
            $adminName,
            $actionText,
            $leadName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logLeadInteractionDeleteAction(Request $request, Admin $admin, string $leadName): void
    {
        $adminName = $admin->full_name ?: 'unknown admin';

        $log = new Log();
        $log->admin_id = $admin->id;
        $log->employee_id = null;
        $log->model = class_basename(LeadInteraction::class);
        $log->action = 'delete';
        $log->description = sprintf(
            'admin(%s) deleted lead interaction for lead(%s)',
            $adminName,
            $leadName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function resolveLeadName(?int $leadId): string
    {
        if (!$leadId) {
            return 'unknown lead';
        }

        $lead = Lead::find($leadId);
        return $lead?->name ?: 'unknown lead';
    }
}
