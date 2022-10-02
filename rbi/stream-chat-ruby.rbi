# typed: strong
module StreamChat
  extend T::Sig
  StringKeyHash = T.type_alias { T::Hash[T.any(String, Symbol), T.untyped] }
  SortArray = T.type_alias { T::Array[{ field: String, direction: Integer }] }
  DEFAULT_BLOCKLIST = 'profanity_en_2020_v1'
  SOFT_DELETE = 'soft'
  HARD_DELETE = 'hard'
  VERSION = '3.1.0'

  class Channel
    extend T::Sig

    sig { returns(T.nilable(String)) }
    attr_reader :id

    sig { returns(String) }
    attr_reader :channel_type

    sig { returns(StringKeyHash) }
    attr_reader :custom_data

    sig { returns(T::Array[StringKeyHash]) }
    attr_reader :members

    sig do
      params(
        client: StreamChat::Client,
        channel_type: String,
        channel_id: T.nilable(String),
        custom_data: T.nilable(StringKeyHash)
      ).void
    end
    def initialize(client, channel_type, channel_id = nil, custom_data = nil); end

    sig { returns(String) }
    def url; end

    sig { params(message_ids: T::Array[String]).returns(StreamChat::StreamResponse) }
    def get_messages(message_ids); end

    sig { params(message: StringKeyHash, user_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def send_message(message, user_id, **options); end

    sig { params(event: StringKeyHash, user_id: String).returns(StreamChat::StreamResponse) }
    def send_event(event, user_id); end

    sig { params(message_id: String, reaction: StringKeyHash, user_id: String).returns(StreamChat::StreamResponse) }
    def send_reaction(message_id, reaction, user_id); end

    sig { params(message_id: String, reaction_type: String, user_id: String).returns(StreamChat::StreamResponse) }
    def delete_reaction(message_id, reaction_type, user_id); end

    sig { params(user_id: String).returns(StreamChat::StreamResponse) }
    def create(user_id); end

    sig { params(options: T.untyped).returns(StreamChat::StreamResponse) }
    def query(**options); end

    sig { params(filter_conditions: StringKeyHash, sort: T.nilable(T::Hash[String, Integer]), options: T.untyped).returns(StreamChat::StreamResponse) }
    def query_members(filter_conditions = {}, sort: nil, **options); end

    sig { params(channel_data: T.nilable(StringKeyHash), update_message: T.nilable(StringKeyHash), options: T.untyped).returns(StreamChat::StreamResponse) }
    def update(channel_data, update_message = nil, **options); end

    sig { params(set: T.nilable(StringKeyHash), unset: T.nilable(T::Array[String])).returns(StreamChat::StreamResponse) }
    def update_partial(set = nil, unset = nil); end

    sig { returns(StreamChat::StreamResponse) }
    def delete; end

    sig { params(options: T.untyped).returns(StreamChat::StreamResponse) }
    def truncate(**options); end

    sig { params(user_id: String, expiration: T.nilable(Integer)).returns(StreamChat::StreamResponse) }
    def mute(user_id, expiration = nil); end

    sig { params(user_id: String).returns(StreamChat::StreamResponse) }
    def unmute(user_id); end

    sig { params(user_ids: T::Array[String], options: T.untyped).returns(StreamChat::StreamResponse) }
    def add_members(user_ids, **options); end

    sig { params(user_ids: T::Array[String], options: T.untyped).returns(StreamChat::StreamResponse) }
    def invite_members(user_ids, **options); end

    sig { params(user_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def accept_invite(user_id, **options); end

    sig { params(user_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def reject_invite(user_id, **options); end

    sig { params(user_ids: T::Array[String]).returns(StreamChat::StreamResponse) }
    def add_moderators(user_ids); end

    sig { params(user_ids: T::Array[String]).returns(StreamChat::StreamResponse) }
    def remove_members(user_ids); end

    sig { params(members: T::Array[StringKeyHash], message: T.nilable(StringKeyHash)).returns(StreamChat::StreamResponse) }
    def assign_roles(members, message = nil); end

    sig { params(user_ids: T::Array[String]).returns(StreamChat::StreamResponse) }
    def demote_moderators(user_ids); end

    sig { params(user_id: String, options: StringKeyHash).returns(StreamChat::StreamResponse) }
    def mark_read(user_id, **options); end

    sig { params(parent_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def get_replies(parent_id, **options); end

    sig { params(message_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def get_reactions(message_id, **options); end

    sig { params(user_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def ban_user(user_id, **options); end

    sig { params(user_id: String).returns(StreamChat::StreamResponse) }
    def unban_user(user_id); end

    sig { params(user_id: String).returns(StreamChat::StreamResponse) }
    def hide(user_id); end

    sig { params(user_id: String).returns(StreamChat::StreamResponse) }
    def show(user_id); end

    sig { params(url: String, user: StringKeyHash, content_type: T.nilable(String)).returns(StreamChat::StreamResponse) }
    def send_file(url, user, content_type = nil); end

    sig { params(url: String, user: StringKeyHash, content_type: T.nilable(String)).returns(StreamChat::StreamResponse) }
    def send_image(url, user, content_type = nil); end

    sig { params(url: String).returns(StreamChat::StreamResponse) }
    def delete_file(url); end

    sig { params(url: String).returns(StreamChat::StreamResponse) }
    def delete_image(url); end

    sig { params(payload: StringKeyHash, user_id: String).returns(StringKeyHash) }
    def add_user_id(payload, user_id); end
  end

  class Client
    extend T::Sig
    DEFAULT_BASE_URL = 'https://chat.stream-io-api.com'
    DEFAULT_TIMEOUT = 6.0

    sig { returns(String) }
    attr_reader :api_key

    sig { returns(String) }
    attr_reader :api_secret

    sig { returns(Faraday::Connection) }
    attr_reader :conn

    sig do
      params(
        api_key: String,
        api_secret: String,
        timeout: T.nilable(T.any(Float, String)),
        options: T.untyped
      ).void
    end
    def initialize(api_key, api_secret, timeout = nil, **options); end

    sig { params(options: T.untyped).returns(Client) }
    def self.from_env(**options); end

    sig { params(client: Faraday::Connection).void }
    def set_http_client(client); end

    sig { params(user_id: String, exp: T.nilable(Integer), iat: T.nilable(Integer)).returns(String) }
    def create_token(user_id, exp = nil, iat = nil); end

    sig { params(settings: T.untyped).returns(StreamChat::StreamResponse) }
    def update_app_settings(**settings); end

    sig { returns(StreamChat::StreamResponse) }
    def get_app_settings; end

    sig { params(id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def flag_message(id, **options); end

    sig { params(id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def unflag_message(id, **options); end

    sig { params(filter_conditions: StringKeyHash, options: T.untyped).returns(StreamChat::StreamResponse) }
    def query_message_flags(filter_conditions, **options); end

    sig { params(id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def flag_user(id, **options); end

    sig { params(id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def unflag_user(id, **options); end

    sig { params(options: T.untyped).returns(StreamChat::StreamResponse) }
    def query_flag_reports(**options); end

    sig do
      params(
        report_id: String,
        review_result: String,
        user_id: String,
        details: T.untyped
      ).returns(StreamChat::StreamResponse)
    end
    def review_flag_report(report_id, review_result, user_id, **details); end

    sig { params(id: String).returns(StreamChat::StreamResponse) }
    def get_message(id); end

    sig do
      params(
        filter_conditions: StringKeyHash,
        query: T.any(String, StringKeyHash),
        sort: T.nilable(T::Hash[String, Integer]),
        options: T.untyped
      ).returns(StreamChat::StreamResponse)
    end
    def search(filter_conditions, query, sort: nil, **options); end

    sig { params(users: T::Array[StringKeyHash]).returns(StreamChat::StreamResponse) }
    def update_users(users); end

    sig { params(user: StringKeyHash).returns(StreamChat::StreamResponse) }
    def update_user(user); end

    sig { params(users: T::Array[StringKeyHash]).returns(StreamChat::StreamResponse) }
    def upsert_users(users); end

    sig { params(user: StringKeyHash).returns(StreamChat::StreamResponse) }
    def upsert_user(user); end

    sig { params(updates: T::Array[StringKeyHash]).returns(StreamChat::StreamResponse) }
    def update_users_partial(updates); end

    sig { params(update: StringKeyHash).returns(StreamChat::StreamResponse) }
    def update_user_partial(update); end

    sig { params(user_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def delete_user(user_id, **options); end

    sig { params(user_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def deactivate_user(user_id, **options); end

    sig { params(user_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def reactivate_user(user_id, **options); end

    sig { params(user_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def export_user(user_id, **options); end

    sig { params(target_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def ban_user(target_id, **options); end

    sig { params(target_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def unban_user(target_id, **options); end

    sig { params(target_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def shadow_ban(target_id, **options); end

    sig { params(target_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def remove_shadow_ban(target_id, **options); end

    sig { params(target_id: String, user_id: String).returns(StreamChat::StreamResponse) }
    def mute_user(target_id, user_id); end

    sig { params(target_id: String, user_id: String).returns(StreamChat::StreamResponse) }
    def unmute_user(target_id, user_id); end

    sig { params(user_id: String).returns(StreamChat::StreamResponse) }
    def mark_all_read(user_id); end

    sig { params(message_id: String, user_id: String, expiration: T.nilable(String)).returns(StreamChat::StreamResponse) }
    def pin_message(message_id, user_id, expiration: nil); end

    sig { params(message_id: String, user_id: String).returns(StreamChat::StreamResponse) }
    def unpin_message(message_id, user_id); end

    sig { params(message: StringKeyHash).returns(StreamChat::StreamResponse) }
    def update_message(message); end

    sig do
      params(
        message_id: String,
        updates: StringKeyHash,
        user_id: T.nilable(String),
        options: T.untyped
      ).returns(StreamChat::StreamResponse)
    end
    def update_message_partial(message_id, updates, user_id: nil, **options); end

    sig { params(message_id: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def delete_message(message_id, **options); end

    sig { params(filter_conditions: StringKeyHash, sort: T.nilable(T::Hash[String, Integer]), options: T.untyped).returns(StreamChat::StreamResponse) }
    def query_banned_users(filter_conditions, sort: nil, **options); end

    sig { params(filter_conditions: StringKeyHash, sort: T.nilable(T::Hash[String, Integer]), options: T.untyped).returns(StreamChat::StreamResponse) }
    def query_users(filter_conditions, sort: nil, **options); end

    sig { params(filter_conditions: StringKeyHash, sort: T.nilable(T::Hash[String, Integer]), options: T.untyped).returns(StreamChat::StreamResponse) }
    def query_channels(filter_conditions, sort: nil, **options); end

    sig { params(data: StringKeyHash).returns(StreamChat::StreamResponse) }
    def create_channel_type(data); end

    sig { params(channel_type: String).returns(StreamChat::StreamResponse) }
    def get_channel_type(channel_type); end

    sig { returns(StreamChat::StreamResponse) }
    def list_channel_types; end

    sig { params(channel_type: String, options: T.untyped).returns(StreamChat::StreamResponse) }
    def update_channel_type(channel_type, **options); end

    sig { params(channel_type: String).returns(StreamChat::StreamResponse) }
    def delete_channel_type(channel_type); end

    sig { params(channel_type: String, channel_id: T.nilable(String), data: T.nilable(StringKeyHash)).returns(StreamChat::Channel) }
    def channel(channel_type, channel_id: nil, data: nil); end

    sig do
      params(
        device_id: String,
        push_provider: String,
        user_id: String,
        push_provider_name: T.nilable(String)
      ).returns(StreamChat::StreamResponse)
    end
    def add_device(device_id, push_provider, user_id, push_provider_name = nil); end

    sig { params(device_id: String, user_id: String).returns(StreamChat::StreamResponse) }
    def delete_device(device_id, user_id); end

    sig { params(user_id: String).returns(StreamChat::StreamResponse) }
    def get_devices(user_id); end

    sig do
      params(
        server_side: T::Boolean,
        android: T::Boolean,
        ios: T::Boolean,
        web: T::Boolean,
        endpoints: T::Array[String]
      ).returns(StreamChat::StreamResponse)
    end
    def get_rate_limits(server_side: false, android: false, ios: false, web: false, endpoints: []); end

    sig { params(request_body: String, x_signature: String).returns(T::Boolean) }
    def verify_webhook(request_body, x_signature); end

    sig { params(user_id: String, event: StringKeyHash).returns(StreamChat::StreamResponse) }
    def send_user_event(user_id, event); end

    sig { params(message_id: String, language: String).returns(StreamChat::StreamResponse) }
    def translate_message(message_id, language); end

    sig { params(message_id: String, data: StringKeyHash).returns(StreamChat::StreamResponse) }
    def run_message_action(message_id, data); end

    sig { params(user: StringKeyHash).returns(StreamChat::StreamResponse) }
    def create_guest(user); end

    sig { returns(StreamChat::StreamResponse) }
    def list_blocklists; end

    sig { params(name: String).returns(StreamChat::StreamResponse) }
    def get_blocklist(name); end

    sig { params(name: String, words: T::Array[String]).returns(StreamChat::StreamResponse) }
    def create_blocklist(name, words); end

    sig { params(name: String, words: T::Array[String]).returns(StreamChat::StreamResponse) }
    def update_blocklist(name, words); end

    sig { params(name: String).returns(StreamChat::StreamResponse) }
    def delete_blocklist(name); end

    sig { params(channels: StringKeyHash, options: T.untyped).returns(StreamChat::StreamResponse) }
    def export_channels(*channels, **options); end

    sig { params(task_id: String).returns(StreamChat::StreamResponse) }
    def get_export_channel_status(task_id); end

    sig { params(task_id: String).returns(StreamChat::StreamResponse) }
    def get_task(task_id); end

    sig do
      params(
        user_ids: T::Array[String],
        user: String,
        messages: T.nilable(String),
        conversations: T.nilable(String)
      ).returns(StreamChat::StreamResponse)
    end
    def delete_users(user_ids, user: SOFT_DELETE, messages: nil, conversations: nil); end

    sig { params(cids: T::Array[String], hard_delete: T::Boolean).returns(StreamChat::StreamResponse) }
    def delete_channels(cids, hard_delete: false); end

    sig { params(before: T.any(DateTime, String)).returns(StreamChat::StreamResponse) }
    def revoke_tokens(before); end

    sig { params(user_id: String, before: T.any(DateTime, String)).returns(StreamChat::StreamResponse) }
    def revoke_user_token(user_id, before); end

    sig { params(user_ids: T::Array[String], before: T.any(DateTime, String)).returns(StreamChat::StreamResponse) }
    def revoke_users_token(user_ids, before); end

    sig { params(relative_url: String, params: T.nilable(StringKeyHash), data: T.nilable(StringKeyHash)).returns(StreamChat::StreamResponse) }
    def put(relative_url, params: nil, data: nil); end

    sig { params(relative_url: String, params: T.nilable(StringKeyHash), data: T.nilable(StringKeyHash)).returns(StreamChat::StreamResponse) }
    def post(relative_url, params: nil, data: nil); end

    sig { params(relative_url: String, params: T.nilable(StringKeyHash)).returns(StreamChat::StreamResponse) }
    def get(relative_url, params: nil); end

    sig { params(relative_url: String, params: T.nilable(StringKeyHash)).returns(StreamChat::StreamResponse) }
    def delete(relative_url, params: nil); end

    sig { params(relative_url: String, params: T.nilable(StringKeyHash), data: T.nilable(StringKeyHash)).returns(StreamChat::StreamResponse) }
    def patch(relative_url, params: nil, data: nil); end

    sig do
      params(
        relative_url: String,
        file_url: String,
        user: StringKeyHash,
        content_type: T.nilable(String)
      ).returns(StreamChat::StreamResponse)
    end
    def send_file(relative_url, file_url, user, content_type = nil); end

    sig { params(push_data: StringKeyHash).returns(StreamChat::StreamResponse) }
    def check_push(push_data); end

    sig { params(sqs_key: T.nilable(String), sqs_secret: T.nilable(String), sqs_url: T.nilable(String)).returns(StreamChat::StreamResponse) }
    def check_sqs(sqs_key = nil, sqs_secret = nil, sqs_url = nil); end

    sig { params(command: StringKeyHash).returns(StreamChat::StreamResponse) }
    def create_command(command); end

    sig { params(name: String).returns(StreamChat::StreamResponse) }
    def get_command(name); end

    sig { params(name: String, command: StringKeyHash).returns(StreamChat::StreamResponse) }
    def update_command(name, command); end

    sig { params(name: String).returns(StreamChat::StreamResponse) }
    def delete_command(name); end

    sig { returns(StreamChat::StreamResponse) }
    def list_commands; end

    sig { returns(StreamChat::StreamResponse) }
    def list_permissions; end

    sig { params(id: String).returns(StreamChat::StreamResponse) }
    def get_permission(id); end

    sig { params(permission: StringKeyHash).returns(StreamChat::StreamResponse) }
    def create_permission(permission); end

    sig { params(id: String, permission: StringKeyHash).returns(StreamChat::StreamResponse) }
    def update_permission(id, permission); end

    sig { params(id: String).returns(StreamChat::StreamResponse) }
    def delete_permission(id); end

    sig { params(name: String).returns(StreamChat::StreamResponse) }
    def create_role(name); end

    sig { params(name: String).returns(StreamChat::StreamResponse) }
    def delete_role(name); end

    sig { returns(StreamChat::StreamResponse) }
    def list_roles; end

    sig { params(push_provider: StringKeyHash).returns(StreamChat::StreamResponse) }
    def upsert_push_provider(push_provider); end

    sig { params(type: String, name: String).returns(StreamChat::StreamResponse) }
    def delete_push_provider(type, name); end

    sig { returns(StreamChat::StreamResponse) }
    def list_push_providers; end

    sig { params(filename: String).returns(StreamChat::StreamResponse) }
    def create_import_url(filename); end

    sig { params(path: String, mode: String).returns(StreamChat::StreamResponse) }
    def create_import(path, mode); end

    sig { params(id: String).returns(StreamChat::StreamResponse) }
    def get_import(id); end

    sig { params(options: T.untyped).returns(StreamChat::StreamResponse) }
    def list_imports(options); end

    sig { params(campaign: StringKeyHash).returns(StreamChat::StreamResponse) }
    def create_campaign(campaign); end

    sig { params(campaign_id: String).returns(StreamChat::StreamResponse) }
    def get_campaign(campaign_id); end

    sig { params(options: StringKeyHash).returns(StreamChat::StreamResponse) }
    def list_campaigns(options); end

    sig { params(campaign_id: String, campaign: StringKeyHash).returns(StreamChat::StreamResponse) }
    def update_campaign(campaign_id, campaign); end

    sig { params(campaign_id: String).returns(StreamChat::StreamResponse) }
    def delete_campaign(campaign_id); end

    sig { params(campaign_id: String, send_at: Integer).returns(StreamChat::StreamResponse) }
    def schedule_campaign(campaign_id, send_at); end

    sig { params(campaign_id: String).returns(StreamChat::StreamResponse) }
    def stop_campaign(campaign_id); end

    sig { params(campaign_id: String).returns(StreamChat::StreamResponse) }
    def resume_campaign(campaign_id); end

    sig { params(campaign_id: String, users: T::Array[StringKeyHash]).returns(StreamChat::StreamResponse) }
    def test_campaign(campaign_id, users); end

    sig { params(segment: StringKeyHash).returns(StreamChat::StreamResponse) }
    def create_segment(segment); end

    sig { params(segment_id: String).returns(StreamChat::StreamResponse) }
    def get_segment(segment_id); end

    sig { params(options: StringKeyHash).returns(StreamChat::StreamResponse) }
    def list_segments(options); end

    sig { params(segment_id: String, segment: StringKeyHash).returns(StreamChat::StreamResponse) }
    def update_segment(segment_id, segment); end

    sig { params(segment_id: String).returns(StreamChat::StreamResponse) }
    def delete_segment(segment_id); end

    sig { returns(T::Hash[String, String]) }
    def get_default_params; end

    sig { returns(String) }
    def get_user_agent; end

    sig { returns(T::Hash[String, String]) }
    def get_default_headers; end

    sig { params(response: Faraday::Response).returns(StreamChat::StreamResponse) }
    def parse_response(response); end

    sig do
      params(
        method: Symbol,
        relative_url: String,
        params: T.nilable(StringKeyHash),
        data: T.nilable(StringKeyHash)
      ).returns(StreamChat::StreamResponse)
    end
    def make_http_request(method, relative_url, params: nil, data: nil); end
  end

  class StreamAPIException < StandardError
    extend T::Sig

    sig { returns(Integer) }
    attr_reader :error_code

    sig { returns(String) }
    attr_reader :error_message

    sig { returns(T::Boolean) }
    attr_reader :json_response

    sig { returns(Faraday::Response) }
    attr_reader :response

    sig { params(response: Faraday::Response).void }
    def initialize(response); end

    sig { returns(String) }
    def message; end

    sig { returns(String) }
    def to_s; end
  end

  class StreamChannelException < StandardError
  end

  class StreamRateLimits
    extend T::Sig

    sig { returns(Integer) }
    attr_reader :limit

    sig { returns(Integer) }
    attr_reader :remaining

    sig { returns(Time) }
    attr_reader :reset

    sig { params(limit: String, remaining: String, reset: String).void }
    def initialize(limit, remaining, reset); end
  end

  class StreamResponse
    extend T::Sig
    extend Forwardable

    sig { returns(StreamRateLimits) }
    attr_reader :rate_limit

    sig { returns(Integer) }
    attr_reader :status_code

    sig { returns(StringKeyHash) }
    attr_reader :headers

    sig { returns(T::Hash[T.untyped, T.untyped]) }
    attr_reader :body

    sig { params(body: T::Hash[T.untyped, T.untyped], response: Faraday::Response).void }
    def initialize(body, response); end
  end

  sig { params(sort: T.nilable(T::Hash[String, Integer])).returns(SortArray) }
  def self.get_sort_fields(sort); end
end
