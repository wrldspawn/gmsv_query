#include "core.hpp"
#include "clientmanager.hpp"
#include "main.hpp"

#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/Lua/LuaInterface.h>
#include <GarrysMod/InterfacePointers.hpp>
#include <GarrysMod/FunctionPointers.hpp>
#include <Platform.hpp>

#include <detouring/hook.hpp>

#include <eiface.h>
#include <filesystem_stdio.h>
#include <iserver.h>
#include <threadtools.h>
#include <utlvector.h>
#include <bitbuf.h>
#include <steam/steam_gameserver.h>
#include <game/server/iplayerinfo.h>

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <queue>
#include <string>

#if defined SYSTEM_WINDOWS

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SERVERSECURE_CALLING_CONVENTION __stdcall

#include <WinSock2.h>
#include <Ws2tcpip.h>

#include <unordered_set>
#include <atomic>

typedef int32_t ssize_t;
typedef int32_t recvlen_t;

#elif defined SYSTEM_LINUX

#define SERVERSECURE_CALLING_CONVENTION

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <unordered_set>
#include <atomic>

typedef int32_t SOCKET;
typedef size_t recvlen_t;

static const SOCKET INVALID_SOCKET = -1;

#elif defined SYSTEM_MACOSX

#define SERVERSECURE_CALLING_CONVENTION

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <unordered_set>
#include <atomic>

typedef int32_t SOCKET;
typedef size_t recvlen_t;

static const SOCKET INVALID_SOCKET = -1;

#endif

class CBaseServer;

struct netsocket_t
{
	int32_t nPort;
	bool bListening;
	int32_t hUDP;
	int32_t hTCP;
};

namespace netfilter
{
	struct packet_t
	{
		packet_t( ) :
			address( ),
			address_size( sizeof( address ) )
		{ }

		sockaddr_in address;
		socklen_t address_size;
		std::vector<uint8_t> buffer;
	};

	struct reply_info_t
	{
		bool dontsend;

		std::string game_name;
		std::string map_name;
		std::string game_dir;
		std::string gamemode_name;
		int32_t amt_clients;
		int32_t max_clients;
		int32_t amt_bots;
		char server_type;
		char os_type;
		bool passworded;
		bool secure;
		std::string game_version;
		int32_t udp_port;
		std::string tags;
		int appid;
		uint64_t steamid;
	};

	struct player_t
	{
		byte index;
		std::string name;
		double score;
		double time;

	};

	struct reply_player_t
	{
		bool dontsend;
		bool senddefault;

		byte count;
		std::vector<player_t> players;
	};


	enum class PacketType
	{
		Invalid = -1,
		Good,
		Info,
		Player,
	};

#if defined SYSTEM_WINDOWS

	static constexpr char operating_system_char = 'w';

#elif defined SYSTEM_POSIX

	static constexpr char operating_system_char = 'l';

#elif defined SYSTEM_MACOSX

	static constexpr char operating_system_char = 'm';

#endif

	static CSteamGameServerAPIContext gameserver_context;
	static bool gameserver_context_initialized = false;

	static SourceSDK::FactoryLoader icvar_loader( "vstdlib" );
	static ConVar *sv_visiblemaxplayers = nullptr;

	static SourceSDK::ModuleLoader dedicated_loader( "dedicated" );
	static SourceSDK::FactoryLoader server_loader( "server" );

	static ssize_t SERVERSECURE_CALLING_CONVENTION recvfrom_detour(
		SOCKET s,
		void *buf,
		recvlen_t buflen,
		int32_t flags,
		sockaddr *from,
		socklen_t *fromlen
	);
	typedef decltype( recvfrom_detour ) *recvfrom_t;

#ifdef PLATFORM_WINDOWS

	static Detouring::Hook recvfrom_hook( "ws2_32", "recvfrom", reinterpret_cast<void *>( recvfrom_detour ) );

#else

	static Detouring::Hook recvfrom_hook( "recvfrom", reinterpret_cast<void *>( recvfrom_detour ) );

#endif

	static SOCKET game_socket = INVALID_SOCKET;

	static constexpr size_t threaded_socket_max_buffer = 8192;
	static constexpr size_t threaded_socket_max_queue = 1000;
	static std::atomic_bool threaded_socket_execute( true );
	static ThreadHandle_t threaded_socket_handle = nullptr;
	static std::queue<packet_t> threaded_socket_queue;
	static CThreadFastMutex threaded_socket_mutex;

	static constexpr char default_game_version[] = "2019.11.12";
	static constexpr uint8_t default_proto_version = 17;
	static bool info_cache_enabled = false;
	static reply_info_t reply_info;
	static char info_cache_buffer[1024] = { 0 };
	static bf_write info_cache_packet( info_cache_buffer, sizeof( info_cache_buffer ) );
	static uint32_t info_cache_last_update = 0;
	static uint32_t info_cache_time = 5;

	static reply_player_t reply_player;
	static char player_cache_buffer[1024] = { 0 };
	static bf_write player_cache_packet(player_cache_buffer, sizeof(player_cache_buffer));

	static ClientManager client_manager;

	static constexpr size_t packet_sampling_max_queue = 50;
	static std::queue<packet_t> packet_sampling_queue;
	static CThreadFastMutex packet_sampling_mutex;

	static IServerGameDLL *gamedll = nullptr;
	static IVEngineServer *engine_server = nullptr;
	static IFileSystem *filesystem = nullptr;
	static GarrysMod::Lua::ILuaInterface *lua = nullptr;

	inline const char *IPToString( const in_addr &addr )
	{
		static char buffer[16] = { };
		const char *str =
			inet_ntop( AF_INET, const_cast<in_addr *>( &addr ), buffer, sizeof( buffer ) );
		if( str == nullptr )
			return "unknown";

		return str;
	}

	static void BuildStaticReplyInfo( )
	{
		reply_info.gamemode_name = gamedll->GetGameDescription( );

		{
			reply_info.game_dir.resize( 256 );
			engine_server->GetGameDir( &reply_info.game_dir[0], static_cast<int32_t>( reply_info.game_dir.size( ) ) );
			reply_info.game_dir.resize( std::strlen( reply_info.game_dir.c_str( ) ) );

			size_t pos = reply_info.game_dir.find_last_of( "\\/" );
			if( pos != reply_info.game_dir.npos )
				reply_info.game_dir.erase( 0, pos + 1 );
		}

		reply_info.max_clients = global::server->GetMaxClients( );

		reply_info.udp_port = global::server->GetUDPPort( );

		{
			const IGamemodeSystem::Information &gamemode =
				static_cast<CFileSystem_Stdio *>( filesystem )->Gamemodes( )->Active( );

			reply_info.tags = " gm:";
			reply_info.tags += gamemode.name;

			if( !gamemode.workshopid )
			{
				reply_info.tags += " gmws:";
				reply_info.tags += std::to_string( gamemode.workshopid );
			}
		}

		{
			FileHandle_t file = filesystem->Open( "steam.inf", "r", "GAME" );
			if( file == nullptr )
			{
				reply_info.game_version = default_game_version;
				_DebugWarning( "[Query] Error opening steam.inf\n" );
				return;
			}

			char buff[256] = { 0 };
			bool failed = filesystem->ReadLine( buff, sizeof( buff ), file ) == nullptr;
			filesystem->Close( file );
			if( failed )
			{
				reply_info.game_version = default_game_version;
				_DebugWarning( "[Query] Failed reading steam.inf\n" );
				return;
			}

			reply_info.game_version = &buff[13];

			size_t pos = reply_info.game_version.find_first_of( "\r\n" );
			if( pos != reply_info.game_version.npos )
				reply_info.game_version.erase( pos );
		}
	}

	static void BuildReplyInfo( )
	{
		const char *server_name = global::server->GetName( );

		reply_info.game_name = server_name;

		const char *map_name = global::server->GetMapName( );

		reply_info.map_name = map_name;

		const char *game_dir = reply_info.game_dir.c_str( );

		reply_info.game_dir = game_dir;

		const char *game_desc = reply_info.gamemode_name.c_str( );

		const int32_t appid = engine_server->GetAppID( );

		reply_info.appid = appid;

		const int32_t num_clients = global::server->GetNumClients( );

		reply_info.amt_clients = num_clients;

		int32_t max_players =
			sv_visiblemaxplayers != nullptr ? sv_visiblemaxplayers->GetInt( ) : -1;
		if( max_players <= 0 || max_players > reply_info.max_clients )
			max_players = reply_info.max_clients;

		reply_info.max_clients = max_players;

		const int32_t num_fake_clients = global::server->GetNumFakeClients( );

		reply_info.amt_bots = num_fake_clients;

		const bool has_password = global::server->GetPassword( ) != nullptr;

		reply_info.amt_bots = has_password;

		if( !gameserver_context_initialized )
			gameserver_context_initialized = gameserver_context.Init( );

		bool vac_secure = false;
		if( gameserver_context_initialized )
		{
			ISteamGameServer *steamGS = gameserver_context.SteamGameServer( );
			if( steamGS != nullptr )
				vac_secure = steamGS->BSecure( );
		}

		reply_info.secure = vac_secure;

		const char *game_version = reply_info.game_version.c_str( );

		const int32_t udp_port = reply_info.udp_port;

		const CSteamID *sid = engine_server->GetGameServerSteamID( );
		const uint64_t steamid = sid != nullptr ? sid->ConvertToUint64( ) : 0;
		reply_info.steamid = steamid;
		const bool has_tags = !reply_info.tags.empty( );
		const char *tags = has_tags ? reply_info.tags.c_str( ) : nullptr;

		info_cache_packet.Reset( );

		info_cache_packet.WriteLong( -1 ); // connectionless packet header
		info_cache_packet.WriteByte( 'I' ); // packet type is always 'I'
		info_cache_packet.WriteByte( default_proto_version );
		info_cache_packet.WriteString( server_name );
		info_cache_packet.WriteString( map_name );
		info_cache_packet.WriteString( game_dir );
		info_cache_packet.WriteString( game_desc );
		info_cache_packet.WriteShort( appid );
		info_cache_packet.WriteByte( num_clients );
		info_cache_packet.WriteByte( max_players );
		info_cache_packet.WriteByte( num_fake_clients );
		info_cache_packet.WriteByte( 'd' ); // dedicated server identifier
		info_cache_packet.WriteByte( operating_system_char );
		info_cache_packet.WriteByte( has_password ? 1 : 0 );
		info_cache_packet.WriteByte( vac_secure );
		info_cache_packet.WriteString( game_version );
		// 0x80 - port number is present
		// 0x10 - server steamid is present
		// 0x20 - tags are present
		// 0x01 - game long appid is present
		info_cache_packet.WriteByte( 0x80 | 0x10 | ( has_tags ? 0x20 : 0x00 ) | 0x01 );
		info_cache_packet.WriteShort( udp_port );
		info_cache_packet.WriteLongLong( steamid );
		if( has_tags )
			info_cache_packet.WriteString( tags );
		info_cache_packet.WriteLongLong( appid );
	}

		reply_info_t CallInfoHook(const sockaddr_in &from)
	{
		char hook[] = "A2S_INFO";

		/*if (!ThreadInMainThread()) {
			Warning("[%s] Called outside of main thread!\n", hook);
			return reply_info;
		}*/

		lua->GetField(GarrysMod::Lua::INDEX_GLOBAL, "hook");
		if (!lua->IsType(-1, GarrysMod::Lua::Type::TABLE))
		{
			lua->Pop(1);
			Warning("[%s] Missing hook table!\n", hook);
			return reply_info;
		}

		lua->GetField(-1, "Run");
		if (!lua->IsType(-1, GarrysMod::Lua::Type::FUNCTION))
		{
			lua->Pop(2);
			Warning("[%s] hook.Run is not a function!\n", hook);
			return reply_info;
		} else {
			lua->Remove(-2);
			lua->PushString(hook);
		}

		lua->PushString(inet_ntoa(from.sin_addr));
		lua->PushNumber(27015);

		lua->CreateTable();

		lua->PushString(reply_info.game_name.c_str());
		lua->SetField(-2, "name");//

		lua->PushString(reply_info.map_name.c_str());
		lua->SetField(-2, "map");

		lua->PushString(reply_info.game_dir.c_str());
		lua->SetField(-2, "folder");//

		lua->PushString(reply_info.gamemode_name.c_str());
		lua->SetField(-2, "gamemode");

		lua->PushNumber(reply_info.amt_clients);
		lua->SetField(-2, "players");

		lua->PushNumber(reply_info.max_clients);
		lua->SetField(-2, "maxplayers");

		lua->PushNumber(reply_info.amt_bots);
		lua->SetField(-2, "bots");

		lua->PushString(&reply_info.server_type);
		lua->SetField(-2, "servertype");

		lua->PushString(&reply_info.os_type);
		lua->SetField(-2, "os");

		lua->PushBool(reply_info.passworded);
		lua->SetField(-2, "passworded");

		lua->PushBool(reply_info.secure);
		lua->SetField(-2, "VAC");

		lua->PushNumber(reply_info.udp_port);
		lua->SetField(-2, "gameport");

		std::string steamid = std::to_string(reply_info.steamid);
		lua->PushString(steamid.c_str());
		lua->SetField(-2, "steamid");

		lua->PushString(reply_info.tags.c_str());
		lua->SetField(-2, "tags");

		lua->CallFunctionProtected(4, 1, true);

		reply_info_t newreply;
		newreply.dontsend = false;

		newreply.game_name = reply_info.game_name;
		newreply.map_name = reply_info.map_name;
		newreply.game_dir = reply_info.game_dir;
		newreply.gamemode_name = reply_info.gamemode_name;
		newreply.amt_clients = reply_info.amt_clients;
		newreply.max_clients = reply_info.max_clients;
		newreply.amt_bots = reply_info.amt_bots;
		newreply.server_type = reply_info.server_type;
		newreply.os_type = reply_info.os_type;
		newreply.passworded = reply_info.passworded;
		newreply.secure = reply_info.secure;
		newreply.game_version = reply_info.game_version;
		newreply.udp_port = reply_info.udp_port;
		newreply.tags = reply_info.tags;
		newreply.appid = reply_info.appid;
		newreply.steamid = reply_info.steamid;

		if (lua->IsType(-1, GarrysMod::Lua::Type::BOOL))
		{
			if (lua->GetBool(-1))
			{
				newreply = reply_info; // return default when return true
			}
			else
			{
				newreply.dontsend = true; // dont send when return false
			}
		}
		else if (lua->IsType(-1, GarrysMod::Lua::Type::TABLE))
		{
			lua->GetField(-1, "name");
			newreply.game_name = lua->GetString(-1);
			lua->Pop(1);

			lua->GetField(-1, "map");
			newreply.map_name = lua->GetString(-1);
			lua->Pop(1);

			lua->GetField(-1, "folder");
			newreply.game_dir = lua->GetString(-1);
			lua->Pop(1);

			lua->GetField(-1, "gamemode");
			newreply.gamemode_name = lua->GetString(-1);
			lua->Pop(1);

			lua->GetField(-1, "players");
			newreply.amt_clients = lua->GetNumber(-1);
			lua->Pop(1);

			lua->GetField(-1, "maxplayers");
			newreply.max_clients = lua->GetNumber(-1);
			lua->Pop(1);

			lua->GetField(-1, "bots");
			newreply.amt_bots = lua->GetNumber(-1);
			lua->Pop(1);

			lua->GetField(-1, "servertype");
			newreply.server_type = lua->GetString(-1)[0]; //make into char
			lua->Pop(1);

			lua->GetField(-1, "os");
			newreply.os_type = lua->GetString(-1)[0];
			lua->Pop(1);

			lua->GetField(-1, "passworded");
			newreply.passworded = lua->GetBool(-1);
			lua->Pop(1);

			lua->GetField(-1, "VAC");
			newreply.secure = lua->GetBool(-1);
			lua->Pop(1);

			lua->GetField(-1, "gameport");
			newreply.udp_port = lua->GetNumber(-1);
			lua->Pop(1);

			lua->GetField(-1, "steamid");
			newreply.steamid = strtoll(lua->GetString(-1), 0, 10);
			lua->Pop(1);

			lua->GetField(-1, "tags");
			newreply.tags = lua->GetString(-1);
			lua->Pop(1);
		}

		lua->Pop(1);

		return newreply;
	}

	static reply_player_t CallPlayerHook(const sockaddr_in &from)
	{
		reply_player_t newreply;
		newreply.dontsend = false;
		newreply.senddefault = true;


		char hook[] = "A2S_PLAYER";

		/*if (!ThreadInMainThread()) {
			Warning("[%s] Called outside of main thread!\n", hook);
			return newreply;
		}*/

		lua->GetField(GarrysMod::Lua::INDEX_GLOBAL, "hook");
		if (!lua->IsType(-1, GarrysMod::Lua::Type::TABLE))
		{
			lua->Pop(1);
			Warning("[%s] Missing hook table!\n", hook);
			return newreply;
		}

		lua->GetField(-1, "Run");
		if (!lua->IsType(-1, GarrysMod::Lua::Type::FUNCTION))
		{
			lua->Pop(2);
			Warning("[%s] hook.Run is not a function!\n", hook);
			return newreply;
		} else {
			lua->Remove(-2);
			lua->PushString(hook);
		}

		lua->PushString(inet_ntoa(from.sin_addr));
		lua->PushNumber(27015);

		lua->CreateTable();

		for (int i = 0; i < newreply.count; i++)
		{
			player_t player = newreply.players[i];

			lua->CreateTable();

			lua->PushString(player.name.c_str());
			lua->SetField(-2, "name");

			lua->PushNumber(player.score);
			lua->SetField(-2, "score");

			lua->PushNumber(player.time);
			lua->SetField(-2, "time");

			lua->PushNumber(i + 1);
			lua->Push(-2);
			lua->Remove(-3);
			lua->RawSet(-3);
		}

		lua->CallFunctionProtected(4, 1, true);

		if (lua->IsType(-1, GarrysMod::Lua::Type::BOOL))
		{
			if (!lua->GetBool(-1))
			{
				newreply.senddefault = false;
				newreply.dontsend = true; // dont send when return false
			}
		}
		else if (lua->IsType(-1, GarrysMod::Lua::Type::TABLE))
		{
			newreply.senddefault = false;

			int count = lua->ObjLen(-1);
			newreply.count = count;

			std::vector<player_t> newPlayers(count);

			for (int i = 0; i < count; i++)
			{
				player_t newPlayer;
				newPlayer.index = i;

				lua->PushNumber(i + 1);
				lua->GetTable(-2);

				lua->GetField(-1, "name");
				newPlayer.name = lua->GetString(-1);
				lua->Pop(1);

				lua->GetField(-1, "score");
				newPlayer.score = lua->GetNumber(-1);
				lua->Pop(1);

				lua->GetField(-1, "time");
				newPlayer.time = lua->GetNumber(-1);
				lua->Pop(1);

				lua->Pop(1);
				newPlayers.at(i) = newPlayer;
			}

			newreply.players = newPlayers;
		}

		lua->Pop(1);

		return newreply;
	}

	static void BuildReplyInfoPacket(reply_info_t info)
	{
		info_cache_packet.Reset();

		info_cache_packet.WriteLong(-1); // connectionless packet header
		info_cache_packet.WriteByte('I'); // packet type is always 'I'
		info_cache_packet.WriteByte(default_proto_version);

		info_cache_packet.WriteString(info.game_name.c_str());

		info_cache_packet.WriteString(info.map_name.c_str());
		info_cache_packet.WriteString(info.game_dir.c_str());
		info_cache_packet.WriteString(info.gamemode_name.c_str());

		info_cache_packet.WriteShort(info.appid);

		info_cache_packet.WriteByte(info.amt_clients);
		info_cache_packet.WriteByte(info.max_clients);
		info_cache_packet.WriteByte(info.amt_bots);
		info_cache_packet.WriteByte(info.server_type);
		info_cache_packet.WriteByte(info.os_type);
		info_cache_packet.WriteByte(info.passworded);

		// if vac protected, it activates itself some time after startup
		info_cache_packet.WriteByte(info.secure);
		info_cache_packet.WriteString(info.game_version.c_str());

		bool notags = info.tags.empty();
		// 0x80 - port number is present
		// 0x10 - server steamid is present
		// 0x20 - tags are present
		// 0x01 - game long appid is present
		info_cache_packet.WriteByte(0x80 | 0x10 | (notags ? 0x00 : 0x20) | 0x01);
		info_cache_packet.WriteShort(info.udp_port);
		info_cache_packet.WriteLongLong(info.steamid);
		if (!notags)
			info_cache_packet.WriteString(info.tags.c_str());
		info_cache_packet.WriteLongLong(info.appid);
	}

	static void BuildReplyPlayerPacket(reply_player_t r_player)
	{
		player_cache_packet.Reset();

		player_cache_packet.WriteLong(-1); // connectionless packet header
		player_cache_packet.WriteByte('D'); // packet type is always 'D'

		player_cache_packet.WriteByte(r_player.count);
		for (int i = 0; i < r_player.count; i++)
		{
			player_t player = r_player.players[i];
			player_cache_packet.WriteByte(i);
			player_cache_packet.WriteString(player.name.c_str());
			player_cache_packet.WriteLong(player.score);
			player_cache_packet.WriteFloat(player.time);
		}

	}

	inline PacketType SendInfoCache( const sockaddr_in &from, uint32_t time )
	{
		if( time - info_cache_last_update >= info_cache_time )
		{
			BuildReplyInfo( );
			info_cache_last_update = time;
		}

		reply_info_t info = CallInfoHook(from);
		if(info.dontsend)
			return PacketType::Invalid;

		BuildReplyInfoPacket(info);

		sendto(
			game_socket,
			reinterpret_cast<char *>( info_cache_packet.GetData( ) ),
			info_cache_packet.GetNumBytesWritten( ),
			0,
			reinterpret_cast<const sockaddr *>( &from ),
			sizeof( from )
		);

		_DebugWarning( "[Query] Handled %s info request using cache\n", IPToString( from.sin_addr ) );

		return PacketType::Invalid; // we've handled it
	}

	inline PacketType HandleInfoQuery( const sockaddr_in &from )
	{
		const uint32_t time = static_cast<uint32_t>( Plat_FloatTime( ) );
		if( !client_manager.CheckIPRate( from.sin_addr.s_addr, time ) )
		{
			_DebugWarning( "[Query] Client %s hit rate limit\n", IPToString( from.sin_addr ) );
			return PacketType::Invalid;
		}

		if( info_cache_enabled )
			return SendInfoCache( from, time );

		return PacketType::Good;
	}

	static PacketType HandlePlayerQuery(const sockaddr_in &from)
	{
		_DebugWarning("[Query] Handling A2S_PLAYER from %s\n",IPToString( from.sin_addr ));
		reply_player_t player = CallPlayerHook(from);

		if (player.senddefault)
			return PacketType::Good;

		if (player.dontsend)
			return PacketType::Invalid; // dont send it

		BuildReplyPlayerPacket(player);

		sendto(
			game_socket,
			reinterpret_cast<char *>(player_cache_packet.GetData()),
			player_cache_packet.GetNumBytesWritten(),
			0,
			reinterpret_cast<const sockaddr *>(&from),
			sizeof(from)
		);

		return PacketType::Invalid; // we've handled it
	}

	static PacketType ClassifyPacket( const uint8_t *data, int32_t len, const sockaddr_in &from )
	{
		if( len == 0 )
		{
			_DebugWarning(
				"[Query] Bad OOB! len: %d from %s\n",
				len,
				IPToString( from.sin_addr )
			);
			return PacketType::Invalid;
		}

		if( len < 5 )
			return PacketType::Good;

		const int32_t channel = *reinterpret_cast<const int32_t *>( data );
		if( channel == -2 )
		{
			_DebugWarning(
				"[Query] Bad OOB! len: %d, channel: 0x%X from %s\n",
				len,
				channel,
				IPToString( from.sin_addr )
			);
			return PacketType::Invalid;
		}

		if( channel != -1 )
			return PacketType::Good;

		const uint8_t type = *( data + 4 );
		if (type == 'U')
			return PacketType::Player;

		return type == 'T' ? PacketType::Info : PacketType::Good;
	}

	inline int32_t HandleNetError( int32_t value )
	{
		if( value == -1 )

#if defined SYSTEM_WINDOWS

			WSASetLastError( WSAEWOULDBLOCK );

#elif defined SYSTEM_POSIX

			errno = EWOULDBLOCK;

#endif

		return value;
	}

	inline bool IsPacketQueueFull( )
	{
		AUTO_LOCK( threaded_socket_mutex );
		return threaded_socket_queue.size( ) >= threaded_socket_max_queue;
	}

	inline bool PopPacketFromQueue( packet_t &p )
	{
		AUTO_LOCK( threaded_socket_mutex );

		if( threaded_socket_queue.empty( ) )
			return false;

		p = std::move( threaded_socket_queue.front( ) );
		threaded_socket_queue.pop( );
		return true;
	}

	inline void PushPacketToQueue( packet_t &&p )
	{
		AUTO_LOCK( threaded_socket_mutex );
		threaded_socket_queue.emplace( std::move( p ) );
	}


	static ssize_t ReceiveAndAnalyzePacket(
		SOCKET s,
		void *buf,
		recvlen_t buflen,
		int32_t flags,
		sockaddr *from,
		socklen_t *fromlen
	)
	{
		auto trampoline = recvfrom_hook.GetTrampoline<recvfrom_t>( );
		if( trampoline == nullptr )
			return -1;

		const ssize_t len = trampoline( s, buf, buflen, flags, from, fromlen );
		_DebugWarning( "[Query] Called recvfrom on socket %d and received %d bytes\n", s, len );
		if( len == -1 )
			return -1;

		const uint8_t *buffer = reinterpret_cast<uint8_t *>( buf );

		const sockaddr_in &infrom = *reinterpret_cast<sockaddr_in *>( from );

		_DebugWarning( "[Query] Address %s was allowed\n", IPToString( infrom.sin_addr ) );

		PacketType type = ClassifyPacket( buffer, len, infrom );
		if( type == PacketType::Info )
			type = HandleInfoQuery( infrom );

		if( type == PacketType::Player )
			type = HandlePlayerQuery( infrom );

		return type != PacketType::Invalid ? len : -1;
	}

	static ssize_t SERVERSECURE_CALLING_CONVENTION recvfrom_detour(
		SOCKET s,
		void *buf,
		recvlen_t buflen,
		int32_t flags,
		sockaddr *from,
		socklen_t *fromlen
	)
	{
		if( s != game_socket )
		{
			_DebugWarning( "[Query] recvfrom detour called with socket %d, passing through\n", s );
			auto trampoline = recvfrom_hook.GetTrampoline<recvfrom_t>( );
			return trampoline != nullptr ? trampoline( s, buf, buflen, flags, from, fromlen ) : -1;
		}

		//_DebugWarning( "[Query] recvfrom detour called with socket %d, detouring\n", s );

		packet_t p;
		const bool has_packet = PopPacketFromQueue( p );
		if( !has_packet )
			return HandleNetError( -1 );

		const ssize_t len = std::min( static_cast<ssize_t>( p.buffer.size( ) ), static_cast<ssize_t>( buflen ) );
		p.buffer.resize( static_cast<size_t>( len ) );
		std::copy( p.buffer.begin( ), p.buffer.end( ), static_cast<uint8_t *>( buf ) );

		const socklen_t addrlen = std::min( *fromlen, p.address_size );
		std::memcpy( from, &p.address, static_cast<size_t>( addrlen ) );
		*fromlen = addrlen;

		return len;
	}

	static uintp PacketReceiverThread( void * )
	{
		while( threaded_socket_execute )
		{
			if( IsPacketQueueFull( ) )
			{
				_DebugWarning( "[Query] Packet queue is full, sleeping for 100ms\n" );
				ThreadSleep( 100 );
				continue;
			}

			fd_set readables;
			FD_ZERO( &readables );
			FD_SET( game_socket, &readables );
			timeval timeout = { 0, 100000 };
			const int32_t res = select( game_socket + 1, &readables, nullptr, nullptr, &timeout );
			if( res == -1 || !FD_ISSET( game_socket, &readables ) )
				continue;

			_DebugWarning( "[Query] Select passed\n" );

			packet_t p;
			p.buffer.resize( threaded_socket_max_buffer );
			const ssize_t len = ReceiveAndAnalyzePacket(
				game_socket,
				p.buffer.data( ),
				static_cast<recvlen_t>( threaded_socket_max_buffer ),
				0,
				reinterpret_cast<sockaddr *>( &p.address ),
				&p.address_size
			);
			if( len == -1 )
				continue;

			_DebugWarning( "[Query] Pushing packet to queue\n" );

			p.buffer.resize( static_cast<size_t>( len ) );

			PushPacketToQueue( std::move( p ) );
		}

		return 0;
	}

	LUA_FUNCTION_STATIC( EnableInfoCache )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Bool );
		info_cache_enabled = LUA->GetBool( 1 );
		return 0;
	}



	void Initialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		lua = static_cast<GarrysMod::Lua::ILuaInterface *>(LUA);
		if( !server_loader.IsValid( ) )
			LUA->ThrowError( "unable to get server factory" );

		ICvar *icvar = InterfacePointers::Cvar( );
		if( icvar != nullptr )
			sv_visiblemaxplayers = icvar->FindVar( "sv_visiblemaxplayers" );

		gamedll = InterfacePointers::ServerGameDLL( );
		if( gamedll == nullptr )
			LUA->ThrowError( "failed to load required IServerGameDLL interface" );

		engine_server = InterfacePointers::VEngineServer( );
		if( engine_server == nullptr )
			LUA->ThrowError( "failed to load required IVEngineServer interface" );

		filesystem = InterfacePointers::FileSystem( );
		if( filesystem == nullptr )
			LUA->ThrowError( "failed to initialize IFileSystem" );

		const FunctionPointers::GMOD_GetNetSocket_t GetNetSocket = FunctionPointers::GMOD_GetNetSocket( );
		if( GetNetSocket != nullptr )
		{
			const netsocket_t *net_socket = GetNetSocket( 1 );
			if( net_socket != nullptr )
				game_socket = net_socket->hUDP;
		}

		if( game_socket == INVALID_SOCKET )
			LUA->ThrowError( "got an invalid server socket" );

		if( !recvfrom_hook.Enable( ) )
			LUA->ThrowError( "failed to detour recvfrom" );

		threaded_socket_execute = true;
		threaded_socket_handle = CreateSimpleThread( PacketReceiverThread, nullptr );
		if( threaded_socket_handle == nullptr )
			LUA->ThrowError( "unable to create thread" );

		BuildStaticReplyInfo( );

		LUA->PushCFunction( EnableInfoCache );
		LUA->SetField( -2, "EnableInfoDetour" );

	}

	void Deinitialize( GarrysMod::Lua::ILuaBase * )
	{
		if( threaded_socket_handle != nullptr )
		{
			threaded_socket_execute = false;
			ThreadJoin( threaded_socket_handle );
			ReleaseThreadHandle( threaded_socket_handle );
			threaded_socket_handle = nullptr;
		}

		recvfrom_hook.Destroy( );
	}
}
