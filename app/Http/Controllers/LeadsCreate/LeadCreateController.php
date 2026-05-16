<?php

namespace App\Http\Controllers\LeadsCreate;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Employee;
use App\Models\Log;
use App\Models\Notification;
use App\Models\Lead_Create;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class LeadCreateController extends Controller
{
    public function index(Request $request)
    {
        $actor = $this->getAuthenticatedActor($request);
        if (!$actor) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'string', 'max:100'],
            'project_code' => ['nullable', 'string', 'max:255'],
            'attended_by' => ['nullable', 'integer', 'exists:employees,id'],
        ]);

        $query = Lead_Create::with(['attendedBy', 'createdBy'])->where('is_deleted', false);

        if (!empty($validated['status'])) {
            $query->where('status', $validated['status']);
        }

        if (!empty($validated['project_code'])) {
            $query->where('project_code', $validated['project_code']);
        }

        if (!empty($validated['attended_by'])) {
            $query->where('attended_by', (int) $validated['attended_by']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('name', 'like', '%' . $search . '%')
                    ->orWhere('email', 'like', '%' . $search . '%')
                    ->orWhere('phone', 'like', '%' . $search . '%')
                    ->orWhere('company', 'like', '%' . $search . '%')
                    ->orWhere('project_code', 'like', '%' . $search . '%')
                    ->orWhere('project_interested', 'like', '%' . $search . '%')
                    ->orWhere('location', 'like', '%' . $search . '%')
                    ->orWhere('remarks', 'like', '%' . $search . '%');
            });
        }

        $leads = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Lead creates fetched successfully.',
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
        $actor = $this->getAuthenticatedActor($request);
        if (!$actor) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid token is required.',
            ], 401);
        }

        $validated = $request->validate([
            'name' => ['nullable', 'string', 'max:255'],
            'email' => ['nullable', 'email', 'max:255'],
            'phone' => ['nullable', 'string', 'max:30'],
            'company' => ['nullable', 'string', 'max:255'],
            'project_code' => ['nullable', 'string', 'max:255'],
            'date' => ['nullable', 'date'],
            'remarks' => ['nullable', 'string'],
            'project_interested' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'string', 'max:100'],
            'location' => ['nullable', 'string', 'max:255'],
            'attended_by' => ['nullable', 'integer', 'exists:employees,id'],
        ]);

        $lead = new Lead_Create();
        $lead->name = $validated['name'] ?? null;
        $lead->email = $validated['email'] ?? null;
        $lead->phone = $validated['phone'] ?? null;
        $lead->company = $validated['company'] ?? null;
        $lead->project_code = $validated['project_code'] ?? null;
        $lead->date = $validated['date'] ?? null;
        $lead->remarks = $validated['remarks'] ?? null;
        $lead->project_interested = $validated['project_interested'] ?? null;
        $lead->created_by = $actor['type'] === 'admin' ? $actor['model']->id : null;
        $lead->status = $validated['status'] ?? 'active';
        $lead->location = $validated['location'] ?? null;
        $lead->attended_by = $validated['attended_by'] ?? ($actor['type'] === 'employee' ? $actor['model']->id : null);
        $lead->is_deleted = false;
        $lead->deleted_at = null;
        $lead->save();
        $this->logLeadCreateAction($request, $actor, $lead, 'create', 'created lead create');
        $this->createLeadCreateNotification($actor, $lead, 'created');

        return response()->json([
            'status' => true,
            'message' => 'Lead create created successfully.',
            'data' => $lead,
        ], 201);
    }

    public function show(Request $request, int $id)
    {
        $actor = $this->getAuthenticatedActor($request);
        if (!$actor) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid token is required.',
            ], 401);
        }

        $lead = Lead_Create::with(['attendedBy', 'createdBy'])->where('is_deleted', false)->find($id);

        if (!$lead) {
            return response()->json([
                'status' => false,
                'message' => 'Lead create not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Lead create fetched successfully.',
            'data' => $lead,
        ]);
    }

    public function update(Request $request, int $id)
    {
        $actor = $this->getAuthenticatedActor($request);
        if (!$actor) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid token is required.',
            ], 401);
        }

        $lead = Lead_Create::where('is_deleted', false)->find($id);

        if (!$lead) {
            return response()->json([
                'status' => false,
                'message' => 'Lead create not found.',
            ], 404);
        }

        $validated = $request->validate([
            'name' => ['sometimes', 'nullable', 'string', 'max:255'],
            'email' => ['sometimes', 'nullable', 'email', 'max:255'],
            'phone' => ['sometimes', 'nullable', 'string', 'max:30'],
            'company' => ['sometimes', 'nullable', 'string', 'max:255'],
            'project_code' => ['sometimes', 'nullable', 'string', 'max:255'],
            'date' => ['sometimes', 'nullable', 'date'],
            'remarks' => ['sometimes', 'nullable', 'string'],
            'project_interested' => ['sometimes', 'nullable', 'string', 'max:255'],
            'status' => ['sometimes', 'nullable', 'string', 'max:100'],
            'location' => ['sometimes', 'nullable', 'string', 'max:255'],
            'attended_by' => ['sometimes', 'nullable', 'integer', 'exists:employees,id'],
        ]);

        if (array_key_exists('name', $validated)) {
            $lead->name = $validated['name'];
        }
        if (array_key_exists('email', $validated)) {
            $lead->email = $validated['email'];
        }
        if (array_key_exists('phone', $validated)) {
            $lead->phone = $validated['phone'];
        }
        if (array_key_exists('company', $validated)) {
            $lead->company = $validated['company'];
        }
        if (array_key_exists('project_code', $validated)) {
            $lead->project_code = $validated['project_code'];
        }
        if (array_key_exists('date', $validated)) {
            $lead->date = $validated['date'];
        }
        if (array_key_exists('remarks', $validated)) {
            $lead->remarks = $validated['remarks'];
        }
        if (array_key_exists('project_interested', $validated)) {
            $lead->project_interested = $validated['project_interested'];
        }
        if (array_key_exists('status', $validated)) {
            $lead->status = $validated['status'] ?: 'active';
        }
        if (array_key_exists('location', $validated)) {
            $lead->location = $validated['location'];
        }
        if (array_key_exists('attended_by', $validated)) {
            $lead->attended_by = $validated['attended_by'];
        }

        $lead->save();
        $this->logLeadCreateAction($request, $actor, $lead, 'update', 'updated lead create');
        $this->createLeadCreateNotification($actor, $lead, 'updated');

        return response()->json([
            'status' => true,
            'message' => 'Lead create updated successfully.',
            'data' => $lead,
        ]);
    }

    public function destroy(Request $request, int $id)
    {
        $actor = $this->getAuthenticatedActor($request);
        if (!$actor) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized. Valid token is required.',
            ], 401);
        }

        $lead = Lead_Create::where('is_deleted', false)->find($id);

        if (!$lead) {
            return response()->json([
                'status' => false,
                'message' => 'Lead create not found.',
            ], 404);
        }

        $lead->is_deleted = true;
        $lead->deleted_at = now();
        $lead->status = 'deleted';
        $lead->save();
        $this->logLeadDeleteAction($request, $actor, $lead);
        $this->createLeadCreateNotification($actor, $lead, 'deleted');

        return response()->json([
            'status' => true,
            'message' => 'Lead create deleted successfully.',
        ]);
    }

    private function getAuthenticatedActor(Request $request): ?array
    {
        $token = $request->bearerToken();
        if (!$token) {
            return null;
        }

        $payload = $this->decodeJwtToken($token);
        if (!$payload) {
            return null;
        }

        $role = strtolower((string) ($payload['role'] ?? ''));
        $actorId = (int) ($payload['sub'] ?? 0);
        if ($actorId <= 0) {
            return null;
        }

        if (in_array($role, ['admin', 'sub_admin', 'subadmin'], true)) {
            $admin = Admin::find($actorId);
            return $admin ? ['type' => 'admin', 'model' => $admin] : null;
        }

        if ($role === 'employee') {
            $employee = Employee::find($actorId);
            return $employee ? ['type' => 'employee', 'model' => $employee] : null;
        }

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

    private function logLeadCreateAction(
        Request $request,
        array $actor,
        Lead_Create $lead,
        string $action,
        string $actionText
    ): void {
        $actorName = $actor['type'] === 'admin' 
            ? ($actor['model']->full_name ?: 'unknown admin')
            : ($actor['model']->emp_name ?: 'unknown employee');
        
        $leadName = $lead->name ?: 'unknown lead create';

        $log = new Log();
        if ($actor['type'] === 'admin') {
            $log->admin_id = $actor['model']->id;
            $log->employee_id = null;
        } else {
            $log->admin_id = null;
            $log->employee_id = $actor['model']->id;
        }
        $log->model = class_basename($lead);
        $log->action = $action;
        $log->description = sprintf(
            '%s(%s) %s (%s)',
            $actor['type'],
            $actorName,
            $actionText,
            $leadName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function logLeadDeleteAction(Request $request, array $actor, Lead_Create $lead): void
    {
        $actorName = $actor['type'] === 'admin' 
            ? ($actor['model']->full_name ?: 'unknown admin')
            : ($actor['model']->emp_name ?: 'unknown employee');

        $leadName = $lead->name ?: 'unknown lead create';

        $log = new Log();
        if ($actor['type'] === 'admin') {
            $log->admin_id = $actor['model']->id;
            $log->employee_id = null;
        } else {
            $log->admin_id = null;
            $log->employee_id = $actor['model']->id;
        }
        $log->model = class_basename(Lead_Create::class);
        $log->action = 'delete';
        $log->description = sprintf(
            '%s(%s) deleted lead create (%s)',
            $actor['type'],
            $actorName,
            $leadName
        );
        $log->ip_address = $request->ip();
        $log->user_agent = (string) $request->userAgent();
        $log->save();
    }

    private function createLeadCreateNotification(array $actor, Lead_Create $lead, string $action): void
    {
        $actorName = $actor['type'] === 'admin' 
            ? ($actor['model']->full_name ?: 'unknown admin')
            : ($actor['model']->emp_name ?: 'unknown employee');

        $leadName = $lead->name ?: 'unknown lead create';

        $notification = new Notification();
        if ($actor['type'] === 'admin') {
            $notification->admin_id = $actor['model']->id;
            $notification->employee_id = null;
        } else {
            $notification->admin_id = null;
            $notification->employee_id = $actor['model']->id;
        }
        $notification->title = 'Lead create ' . $action;
        $notification->message = sprintf(
            '%s(%s) %s lead create (%s)',
            $actor['type'],
            $actorName,
            $action,
            $leadName
        );
        $notification->is_read = false;
        $notification->save();
    }
}
