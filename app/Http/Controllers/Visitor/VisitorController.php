<?php

namespace App\Http\Controllers\Visitor;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use App\Models\Visitor;

class VisitorController extends Controller
{
    public function index(Request $request)
    {
        $validated = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
        ]);

        $query = Visitor::query();
        $search = trim((string) ($validated['search'] ?? ''));

        if ($search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder->where('name', 'like', '%' . $search . '%')
                    ->orWhere('email', 'like', '%' . $search . '%')
                    ->orWhere('phone', 'like', '%' . $search . '%')
                    ->orWhere('purpose', 'like', '%' . $search . '%');
            });
        }

        $visitors = $query->latest()->paginate(10);

        return response()->json([
            'status' => true,
            'message' => 'Visitors fetched successfully.',
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
            'email' => ['required', 'email', 'max:255', 'unique:visitors,email'],
            'phone' => ['nullable', 'string', 'max:30'],
            'purpose' => ['nullable', 'string', 'max:1000'],
        ]);

        $visitor = new Visitor();
        $visitor->name = $validated['name'];
        $visitor->email = $validated['email'];
        $visitor->phone = $validated['phone'] ?? null;
        $visitor->purpose = $validated['purpose'] ?? null;
        $visitor->save();

        return response()->json([
            'status' => true,
            'message' => 'Visitor created successfully.',
            'data' => $visitor,
        ], 201);
    }

    public function show(int $id)
    {
        $visitor = Visitor::find($id);

        if (!$visitor) {
            return response()->json([
                'status' => false,
                'message' => 'Visitor not found.',
            ], 404);
        }

        return response()->json([
            'status' => true,
            'message' => 'Visitor fetched successfully.',
            'data' => $visitor,
        ]);
    }

    public function update(Request $request, int $id)
    {
        $visitor = Visitor::find($id);

        if (!$visitor) {
            return response()->json([
                'status' => false,
                'message' => 'Visitor not found.',
            ], 404);
        }

        $validated = $request->validate([
            'name' => ['sometimes', 'required', 'string', 'max:255'],
            'email' => ['sometimes', 'required', 'email', 'max:255', Rule::unique('visitors', 'email')->ignore($visitor->id)],
            'phone' => ['nullable', 'string', 'max:30'],
            'purpose' => ['nullable', 'string', 'max:1000'],
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
        if (array_key_exists('purpose', $validated)) {
            $visitor->purpose = $validated['purpose'];
        }

        $visitor->save();

        return response()->json([
            'status' => true,
            'message' => 'Visitor updated successfully.',
            'data' => $visitor,
        ]);
    }

    public function destroy(int $id)
    {
        $visitor = Visitor::find($id);

        if (!$visitor) {
            return response()->json([
                'status' => false,
                'message' => 'Visitor not found.',
            ], 404);
        }

        $visitor->delete();

        return response()->json([
            'status' => true,
            'message' => 'Visitor deleted successfully.',
        ]);
    }
}
