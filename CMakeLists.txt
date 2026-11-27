cmake_minimum_required(VERSION 3.21)
project(rtc_video_sdk VERSION 1.3.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(RTC_BUILD_SHARED_SDK "Build pure C++17 shared library librtc_video_sdk.so with hidden internal symbols" ON)
option(RTC_BUILD_SERVERS    "Build companion P2P WS Signaling and MoQ Relay servers" ON)
option(RTC_BUILD_EXAMPLES   "Build complete C++17 SDK usage examples" ON)
option(RTC_BUILD_TESTS      "Build unit, weak-network E2E, and example verification tests" ON)
option(RTC_ENABLE_DCHECK    "Enable RTC_DCHECK and RTC_DCHECK_RUN_ON assertions even when NDEBUG is defined" ON)
set(RTC_SDK_OUTPUT_DIR "${CMAKE_BINARY_DIR}/sdk_out" CACHE PATH
    "Target directory to automatically export SDK headers and libraries after build (empty to disable)")

# 1. 核心依赖库：Threads、OpenSSL、Boost、libsrtp2
find_package(Threads REQUIRED)
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Boost 1.70 REQUIRED COMPONENTS system thread)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsrtp/CMakeLists.txt")
  set(_rtc_saved_build_shared_libs "${BUILD_SHARED_LIBS}")
  set(ENABLE_OPENSSL ON CACHE BOOL "" FORCE)
  set(LIBSRTP_TEST_APPS OFF CACHE BOOL "" FORCE)
  set(ENABLE_WARNINGS OFF CACHE BOOL "" FORCE)
  set(ENABLE_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)
  set(BUILD_SHARED_LIBS OFF)
  add_subdirectory(third_party/libsrtp EXCLUDE_FROM_ALL)
  set(BUILD_SHARED_LIBS "${_rtc_saved_build_shared_libs}")
  unset(_rtc_saved_build_shared_libs)
  set(RTC_SRTP_TARGET srtp2)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SRTP2 REQUIRED IMPORTED_TARGET libsrtp2)
  set(RTC_SRTP_TARGET PkgConfig::SRTP2)
endif()

# 2. 核心 C++17 目标对象与静态库（Google C++ 代码风格 + 统一日志 + WebRTC P2P + IETF MoQ）
set(RTC_CORE_SOURCES
  src/rtc_base/logging.cc
  src/rtc_base/json_utils.cc
  src/rtc_base/task_queue.cc
  src/rtc_base/packet_slab_pool.cc
  src/rtc_base/timestamp_extrapolator.cc
  src/modules/rtp_rtcp/rtp_packet.cc
  src/modules/rtp_rtcp/rtp_video_packetizer.cc
  src/modules/rtp_rtcp/rtp_packet_history.cc
  src/modules/rtp_rtcp/flexfec_codec.cc
  src/modules/rtp_rtcp/rtcp_packets.cc
  src/modules/pacing/pacing_module.cc
  src/modules/congestion_controller/goog_cc/goog_cc_controller.cc
  src/modules/video_coding/video_coding_module.cc
  src/p2p/stun_turn_ice.cc
  src/pc/dtls_srtp_transport.cc
  src/pc/sctp_data_channel.cc
  src/signaling/wss_signaling_client.cc
  src/moq/quic_congestion_control.cc
  src/moq/asio_quic_transport.cc
  src/moq/http3_webtransport.cc
  src/moq/moq_transport.cc
  src/call/webrtc_p2p_backend.cc
  src/sdk/rtc_video_engine_impl.cc
)

set(RTC_STRICT_CXX_FLAGS -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Wno-unused-parameter)

add_library(rtc_video_objs OBJECT ${RTC_CORE_SOURCES})
target_include_directories(rtc_video_objs
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_options(rtc_video_objs PRIVATE ${RTC_STRICT_CXX_FLAGS})
if(RTC_ENABLE_DCHECK)
  target_compile_definitions(rtc_video_objs PUBLIC RTC_DCHECK_IS_ON=1)
endif()
target_link_libraries(rtc_video_objs
  PUBLIC
    Boost::system
    Boost::thread
    OpenSSL::SSL
    OpenSSL::Crypto
    ${RTC_SRTP_TARGET}
    Threads::Threads
)
set_target_properties(rtc_video_objs PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON
)

add_library(rtc_video_core STATIC $<TARGET_OBJECTS:rtc_video_objs>)
if(TARGET srtp2)
  add_dependencies(rtc_video_core srtp2)
endif()
target_include_directories(rtc_video_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
if(RTC_ENABLE_DCHECK)
  target_compile_definitions(rtc_video_core PUBLIC RTC_DCHECK_IS_ON=1)
endif()
target_link_libraries(rtc_video_core
  PUBLIC
    Boost::system
    Boost::thread
    OpenSSL::SSL
    OpenSSL::Crypto
    ${RTC_SRTP_TARGET}
    Threads::Threads
)

# 3. 纯现代 C++17 动态库 SDK（仅导出标注 RTC_SDK_API 的 C++17 公共类与工厂函数，隐藏全部内部依赖符号）
if(RTC_BUILD_SHARED_SDK)
  if(WIN32)
    add_library(rtc_video_sdk SHARED ${RTC_CORE_SOURCES})
    target_compile_options(rtc_video_sdk PRIVATE ${RTC_STRICT_CXX_FLAGS})
    if(RTC_ENABLE_DCHECK)
      target_compile_definitions(rtc_video_sdk PRIVATE RTC_DCHECK_IS_ON=1)
    endif()
    target_include_directories(rtc_video_sdk PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  else()
    add_library(rtc_video_sdk SHARED $<TARGET_OBJECTS:rtc_video_objs>)
  endif()
  target_compile_definitions(rtc_video_sdk
    PRIVATE RTC_SDK_SHARED_BUILD=1
    INTERFACE RTC_SDK_SHARED_CONSUME=1
  )
  target_include_directories(rtc_video_sdk
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  )
  target_link_libraries(rtc_video_sdk PRIVATE
    $<BUILD_INTERFACE:Boost::system>
    $<BUILD_INTERFACE:Boost::thread>
    $<BUILD_INTERFACE:OpenSSL::SSL>
    $<BUILD_INTERFACE:OpenSSL::Crypto>
    $<BUILD_INTERFACE:${RTC_SRTP_TARGET}>
    $<BUILD_INTERFACE:Threads::Threads>
  )
  set_target_properties(rtc_video_sdk PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
  )
  if(UNIX AND NOT APPLE)
    target_link_options(rtc_video_sdk PRIVATE
      "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/cmake/rtc_video_sdk_cpp17.version"
      "-Wl,--exclude-libs,ALL"
    )
  endif()
endif()

# 4. 配套轻量级服务端（P2P WS 信令服务 + 可选内置 STUN/TURN 中继服务 + MoQ QUIC 中继服务）
if(RTC_BUILD_SERVERS)
  add_library(rtc_companion_servers STATIC
    src/server/p2p_ws_signaling_server.cc
    src/server/stun_turn_relay_server.cc
    src/server/embedded_moq_relay.cc
  )
  target_include_directories(rtc_companion_servers PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_options(rtc_companion_servers PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_companion_servers PUBLIC rtc_video_core)

  add_executable(rtc_p2p_ws_signaling_server examples/p2p_ws_signaling_main.cc)
  target_compile_options(rtc_p2p_ws_signaling_server PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_p2p_ws_signaling_server PRIVATE rtc_companion_servers)

  add_executable(rtc_moq_relay_server examples/moq_relay_main.cc)
  target_compile_options(rtc_moq_relay_server PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_moq_relay_server PRIVATE rtc_companion_servers)
endif()

# 5. 全场景现代 C++17 SDK 使用示例（涵盖 WebRTC P2P、IETF MoQ 与浏览器网关/播放器）
if(RTC_BUILD_EXAMPLES AND RTC_BUILD_SERVERS)
  # 5.1 现代 C++17 WebRTC P2P 完整示例（直连 W3C SDP + WS 自动信令）
  add_executable(rtc_example_cpp17_p2p examples/cpp17_webrtc_p2p_full_demo.cc)
  target_compile_options(rtc_example_cpp17_p2p PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_example_cpp17_p2p PRIVATE
    rtc_companion_servers
    rtc_video_core
  )

  # 5.2 现代 C++17 IETF MoQ 多路推流与多路拉流完整示例
  add_executable(rtc_example_cpp17_moq examples/cpp17_moq_multipull_full_demo.cc)
  target_compile_options(rtc_example_cpp17_moq PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_example_cpp17_moq PRIVATE
    rtc_companion_servers
    rtc_video_core
  )

  # 5.3 浏览器 HTML5 <video> WebRTC P2P HTTP 网关与自测示例
  add_executable(rtc_example_browser_p2p
    examples/browser_webrtc_p2p_gateway_demo.cc
  )
  target_compile_options(rtc_example_browser_p2p PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_example_browser_p2p PRIVATE rtc_video_core)

  # 5.4 浏览器 HTML5 <canvas> IETF MoQ (draft-17) WebTransport + WebCodecs 实时播放器与自测示例
  add_executable(rtc_example_browser_moq
    examples/browser_moq_player_demo.cc
  )
  target_compile_options(rtc_example_browser_moq PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_example_browser_moq PRIVATE
    rtc_companion_servers
    rtc_video_core
  )
endif()

# 6. 单元测试、纯 C++17 动态库隔离验证、弱网端到端（E2E）测试及完整示例验证套件
if(RTC_BUILD_TESTS)
  enable_testing()
  find_package(GTest REQUIRED)

  add_executable(rtc_core_unit_tests tests/rtc_core_unit_tests.cc)
  target_compile_options(rtc_core_unit_tests PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_core_unit_tests PRIVATE
    rtc_video_core
    GTest::gtest
    GTest::gtest_main
  )
  add_test(NAME RtcCoreUnitTests COMMAND rtc_core_unit_tests)

  if(RTC_BUILD_SHARED_SDK)
    add_executable(rtc_cpp17_shared_sdk_test tests/rtc_cpp17_shared_sdk_test.cc)
    target_compile_options(rtc_cpp17_shared_sdk_test PRIVATE ${RTC_STRICT_CXX_FLAGS})
    target_link_libraries(rtc_cpp17_shared_sdk_test PRIVATE
      rtc_video_sdk
      GTest::gtest
      GTest::gtest_main
    )
    add_test(NAME RtcCpp17SharedSdkTests COMMAND rtc_cpp17_shared_sdk_test)
  endif()

  if(RTC_BUILD_SERVERS)
    add_executable(rtc_e2e_integration_tests tests/rtc_e2e_integration_tests.cc)
    target_compile_options(rtc_e2e_integration_tests PRIVATE ${RTC_STRICT_CXX_FLAGS})
    target_link_libraries(rtc_e2e_integration_tests PRIVATE
      rtc_companion_servers
      rtc_video_core
      GTest::gtest
      GTest::gtest_main
    )
    add_test(NAME RtcE2EIntegrationTests COMMAND rtc_e2e_integration_tests)

    add_executable(rtc_real_cc_benchmark_test tests/rtc_real_cc_benchmark_test.cc)
    target_compile_options(rtc_real_cc_benchmark_test PRIVATE ${RTC_STRICT_CXX_FLAGS})
    target_link_libraries(rtc_real_cc_benchmark_test PRIVATE
      rtc_companion_servers
      rtc_video_core
      GTest::gtest
      GTest::gtest_main
    )
    add_test(NAME RtcRealCongestionControlTests COMMAND rtc_real_cc_benchmark_test)

    add_executable(rtc_industry_weaknet_suite_test tests/rtc_industry_weaknet_suite_test.cc)
    target_compile_options(rtc_industry_weaknet_suite_test PRIVATE ${RTC_STRICT_CXX_FLAGS})
    target_link_libraries(rtc_industry_weaknet_suite_test PRIVATE
      rtc_companion_servers
      rtc_video_core
      GTest::gtest
      GTest::gtest_main
    )
    add_test(NAME RtcIndustryWeakNetSuite COMMAND rtc_industry_weaknet_suite_test)
  endif()

  if(RTC_BUILD_EXAMPLES AND RTC_BUILD_SERVERS)
    if(TARGET rtc_example_cpp17_p2p)
      add_test(NAME SdkExampleCpp17WebRtcP2pFull
        COMMAND rtc_example_cpp17_p2p
      )
    endif()
    if(TARGET rtc_example_cpp17_moq)
      add_test(NAME SdkExampleCpp17MoqMultiPullFull
        COMMAND rtc_example_cpp17_moq
      )
    endif()
    if(TARGET rtc_example_browser_p2p)
      add_test(NAME SdkExampleBrowserHttpP2p
        COMMAND rtc_example_browser_p2p --self-test
      )
    endif()
    if(TARGET rtc_example_browser_moq)
      add_test(NAME SdkExampleBrowserMoqPlayer
        COMMAND rtc_example_browser_moq --self-test
      )
    endif()
  endif()
endif()

# 7. SDK 公共头文件、库文件及 CMake 包安装与编译后自动导出规则
set(RTC_PUBLIC_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/include/rtc_video_types.hpp
  ${CMAKE_CURRENT_SOURCE_DIR}/include/rtc_quic_congestion_control.hpp
  ${CMAKE_CURRENT_SOURCE_DIR}/include/rtc_video_engine.hpp
)

install(FILES ${RTC_PUBLIC_HEADERS}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT sdk
)

install(TARGETS rtc_video_core
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT sdk
)

if(TARGET srtp2)
  install(FILES $<TARGET_FILE:srtp2>
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT sdk
  )
endif()

if(RTC_BUILD_SHARED_SDK)
  install(TARGETS rtc_video_sdk
    EXPORT rtc_video_sdkTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT sdk NAMELINK_COMPONENT sdk
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT sdk
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT sdk
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  install(EXPORT rtc_video_sdkTargets
    FILE rtc_video_sdkTargets.cmake
    NAMESPACE rtc::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rtc_video_sdk
    COMPONENT sdk
  )

  configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/rtc_video_sdkConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/rtc_video_sdkConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rtc_video_sdk
  )

  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/rtc_video_sdkConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
  )

  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/rtc_video_sdkConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/rtc_video_sdkConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rtc_video_sdk
    COMPONENT sdk
  )
endif()

if(RTC_BUILD_SERVERS)
  install(TARGETS
    rtc_p2p_ws_signaling_server
    rtc_moq_relay_server
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT servers
  )
endif()

if(NOT "${RTC_SDK_OUTPUT_DIR}" STREQUAL "")
  set(RTC_EXPORT_DEPENDS rtc_video_core)
  if(TARGET srtp2)
    list(APPEND RTC_EXPORT_DEPENDS srtp2)
  endif()
  if(RTC_BUILD_SHARED_SDK)
    list(APPEND RTC_EXPORT_DEPENDS rtc_video_sdk)
  endif()
  add_custom_target(rtc_export_sdk ALL
    COMMAND ${CMAKE_COMMAND} --install "${CMAKE_BINARY_DIR}"
            --config $<CONFIG>
            --prefix "${RTC_SDK_OUTPUT_DIR}"
            --component sdk
    DEPENDS ${RTC_EXPORT_DEPENDS}
    COMMENT "Exporting C++17 SDK headers and libraries to ${RTC_SDK_OUTPUT_DIR}"
  )
endif()
