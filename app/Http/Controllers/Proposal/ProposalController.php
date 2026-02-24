<?php

namespace App\Http\Controllers\Proposal;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Proposal;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class ProposalController extends Controller
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
            'proposal_status' => ['nullable', 'in:sent,rejected,approved'],
            'proposal_code' => ['nullable', 'string', 'max:100'],
            'search' => ['nullable', 'string', 'max:255'],
        ]);

        $query = Proposal::query();

        if (!empty($validated['lead_id'])) {
            $query->where('lead_id', (int) $validated['lead_id']);
        }

        if (!empty($validated['proposal_status'])) {
            $query->where('proposal_status', $validated['proposal_status']);
        }

        if (!empty($validated['proposal_code'])) {
            $query->where('proposal_code', $validated['proposal_code']);
        }

        $search = trim((string) ($validated['search'] ?? ''));
        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('proposal_code', 'like', '%' . $search . '%')
                    ->orWhere('proposal_status', 'like', '%' . $search . '%')
                    ->orWhere('proposal_amount', 'like', '%' . $search . '%');
            });
        }

        $proposals = $query->latest()->paginate(10);
        $proposals->getCollection()->transform(fn (Proposal $proposal) => $this->transformProposal($proposal));

        return response()->json([
            'status' => true,
            'message' => 'Proposals fetched successfully.',
            'data' => $proposals->items(),
            'pagination' => [
                'current_page' => $proposals->currentPage(),
                'last_page' => $proposals->lastPage(),
                'per_page' => $proposals->perPage(),
                'total' => $proposals->total(),
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
            'proposal_amount' => ['required', 'numeric', 'min:0'],
            'proposal_status' => ['nullable', 'in:sent,rejected,approved'],
            'file' => ['nullable', 'file', 'mimes:pdf,doc,docx', 'max:10240'],
        ]);

        $proposal = new Proposal();
        $proposal->lead_id = (int) $validated['lead_id'];
        $proposal->proposal_amount = $validated['proposal_amount'];
        $proposal->proposal_status = $validated['proposal_status'] ?? 'sent';
        $proposal->proposal_code = $this->generateProposalCode();

        if ($request->hasFile('file')) {
            $proposal->file = $request->file('file')->store('proposals', 'public');
        }

        $proposal->save();

        return response()->json([
            'status' => true,
            'message' => 'Proposal created successfully.',
            'data' => $this->transformProposal($proposal),
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

        $proposal = Proposal::find($id);
        if (!$proposal) {
            return response()->json([
                'status' => false,
                'message' => 'Proposal not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Proposal fetched successfully.',
            'data' => $this->transformProposal($proposal),
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

        $proposal = Proposal::find($id);
        if (!$proposal) {
            return response()->json([
                'status' => false,
                'message' => 'Proposal not found.',
            ], 404);
        }

        $validated = $request->validate([
            'lead_id' => ['sometimes', 'required', 'integer', 'exists:leads,id'],
            'proposal_amount' => ['sometimes', 'required', 'numeric', 'min:0'],
            'proposal_status' => ['nullable', 'in:sent,rejected,approved'],
            'file' => ['nullable', 'file', 'mimes:pdf,doc,docx', 'max:10240'],
        ]);

        if (array_key_exists('lead_id', $validated)) {
            $proposal->lead_id = (int) $validated['lead_id'];
        }

        if (array_key_exists('proposal_amount', $validated)) {
            $proposal->proposal_amount = $validated['proposal_amount'];
        }

        if (array_key_exists('proposal_status', $validated)) {
            $proposal->proposal_status = $validated['proposal_status'] ?: 'sent';
        }

        if ($request->hasFile('file')) {
            if (!empty($proposal->file) && Storage::disk('public')->exists($proposal->file)) {
                Storage::disk('public')->delete($proposal->file);
            }
            $proposal->file = $request->file('file')->store('proposals', 'public');
        }

        $proposal->save();

        return response()->json([
            'status' => true,
            'message' => 'Proposal updated successfully.',
            'data' => $this->transformProposal($proposal),
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

        $proposal = Proposal::find($id);
        if (!$proposal) {
            return response()->json([
                'status' => false,
                'message' => 'Proposal not found.',
            ], 404);
        }

        if (!empty($proposal->file) && Storage::disk('public')->exists($proposal->file)) {
            Storage::disk('public')->delete($proposal->file);
        }

        $proposal->delete();

        return response()->json([
            'status' => true,
            'message' => 'Proposal deleted successfully.',
        ]);
    }

    private function transformProposal(Proposal $proposal): array
    {
        $data = $proposal->toArray();
        $data['file'] = $proposal->file ? url(Storage::url($proposal->file)) : null;

        return $data;
    }

    private function generateProposalCode(): string
    {
        do {
            $code = 'BIT-PROP-' . strtoupper(Str::random(8));
        } while (Proposal::where('proposal_code', $code)->exists());

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
}
