<?php

namespace App\Services;

use Ably\AblyRest;

class AblyService
{
    protected AblyRest $ably;

    public function __construct()
    {
        $this->ably = new AblyRest(env('ABLY_KEY'));
    }

    /**
     * Publish message to a chat channel
     */
    public function publishMessage(int $chatId, array $messageData): void
    {
        $channel = $this->ably->channels->get("chat:{$chatId}");
        $channel->publish('new-message', $messageData);
    }

    /**
     * Publish typing indicator
     */
    public function publishTyping(int $chatId, array $userData): void
    {
        $channel = $this->ably->channels->get("chat:{$chatId}");
        $channel->publish('typing', $userData);
    }

    /**
     * Publish stop typing indicator
     */
    public function publishStopTyping(int $chatId, array $userData): void
    {
        $channel = $this->ably->channels->get("chat:{$chatId}");
        $channel->publish('stop-typing', $userData);
    }

    /**
     * Publish message read receipt
     */
    public function publishReadReceipt(int $chatId, array $readData): void
    {
        $channel = $this->ably->channels->get("chat:{$chatId}");
        $channel->publish('message-read', $readData);
    }

    /**
     * Publish notification to specific user
     */
    public function publishToUser(int $userId, string $userType, array $data): void
    {
        $channel = $this->ably->channels->get("user:{$userType}:{$userId}");
        $channel->publish('notification', $data);
    }

    /**
     * Generate token request for frontend client authentication
     */
    public function createTokenRequest(string $clientId): object
    {
        return $this->ably->auth->createTokenRequest([
            'clientId' => $clientId
        ]);
    }
}
