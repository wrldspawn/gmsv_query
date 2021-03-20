#include "main.hpp"
#include "netfilter/core.hpp"
#include "filecheck.hpp"

#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/InterfacePointers.hpp>
#include <Platform.hpp>

#include <iserver.h>

namespace global
{
	SourceSDK::FactoryLoader engine_loader( "engine" );
	IServer *server = nullptr;

	static void PreInitialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		server = InterfacePointers::Server( );
		if( server == nullptr )
			LUA->ThrowError( "failed to dereference IServer" );

		LUA->CreateTable( );

		LUA->PushString( "query 1.0" );
		LUA->SetField( -2, "Version" );

	}

	static void Initialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, "query" );
	}

	static void Deinitialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		LUA->PushNil( );
		LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, "query" );
	}
}

GMOD_MODULE_OPEN( )
{
	global::PreInitialize( LUA );
	netfilter::Initialize( LUA );
	filecheck::Initialize( LUA );
	global::Initialize( LUA );
	return 1;
}

GMOD_MODULE_CLOSE( )
{
	filecheck::Deinitialize( LUA );
	netfilter::Deinitialize( LUA );
	global::Deinitialize( LUA );
	return 0;
}
