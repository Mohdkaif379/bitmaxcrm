<?php

namespace App\Http\Controllers\VisitorInvited;

use App\Http\Controllers\Controller;
use App\Models\VisitorInvited;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Illuminate\Support\Str;

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

        return response()->json([
            'status' => true,
            'message' => 'Visitor invite updated successfully.',
            'data' => $visitor,
        ]);
    }

    public function destroy(int $id)
    {
        $visitor = VisitorInvited::find($id);

        if (!$visitor) {
            return response()->json([
                'status' => false,
                'message' => 'Visitor invite not found.',
            ], 404);
        }

        $visitor->delete();

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
}
