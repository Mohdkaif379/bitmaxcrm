<?php

namespace App\Http\Controllers\ElasticSearch;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Models\Employee;
use App\Models\Task;
use App\Models\VisitorInvited;
use Illuminate\Http\Request;

class ElasticSearchController extends Controller
{
	public function search(Request $request)
	{
		$validated = $request->validate([
			'model' => ['required', 'string', 'in:employee,task,admin,visitor'],
			'q' => ['required', 'string', 'min:1'],
			'per_page' => ['nullable', 'integer', 'min:1', 'max:100'],
		]);

		$modelKey = strtolower($validated['model']);
		$queryText = trim($validated['q']);
		$perPage = (int) ($validated['per_page'] ?? 15);

		$map = [
			'employee' => [
				'class' => Employee::class,
				'columns' => ['emp_name', 'emp_email', 'emp_phone', 'emp_code'],
			],
			'task' => [
				'class' => Task::class,
				'columns' => ['task_name', 'assignment_type'],
			],
			'admin' => [
				'class' => Admin::class,
				'columns' => ['full_name', 'email', 'number'],
			],
			'visitor' => [
				'class' => VisitorInvited::class,
				'columns' => ['name', 'email', 'phone', 'invite_code', 'contact_person_name'],
			],
		];

		$entry = $map[$modelKey] ?? null;
		if (!$entry) {
			return response()->json(['status' => false, 'message' => 'Invalid model specified.'], 422);
		}

		$modelClass = $entry['class'];
		$columns = $entry['columns'];

		$qb = $modelClass::query();
		$qb->where(function ($q) use ($columns, $queryText) {
			foreach ($columns as $col) {
				$q->orWhere($col, 'like', '%' . $queryText . '%');
			}
		});

		$results = $qb->paginate($perPage)->appends($request->query());

		$items = $results->getCollection()->map(function ($item) {
			$arr = $item->toArray();
			if (isset($arr['profile_photo']) && $arr['profile_photo']) {
				$arr['profile_photo'] = $this->publicStorageUrl($arr['profile_photo']);
			}
			if (isset($arr['profile_image']) && $arr['profile_image']) {
				$arr['profile_image'] = $this->publicStorageUrl($arr['profile_image']);
			}
			return $arr;
		})->values();

		return response()->json([
			'status' => true,
			'message' => 'Search results',
			'data' => $items,
			'pagination' => [
				'current_page' => $results->currentPage(),
				'last_page' => $results->lastPage(),
				'per_page' => $results->perPage(),
				'total' => $results->total(),
			],
		]);
	}

	private function publicStorageUrl(string $relativePath): string
	{
		$clean = ltrim($relativePath, '/');
		$base = rtrim((string) config('app.url', ''), '/');
		return $base . '/public/storage/' . $clean;
	}
}
