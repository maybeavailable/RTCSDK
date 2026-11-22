cmake_minimum_required(VERSION 3.21)
project(rtc_video_sdk VERSION 1.2.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(RTC_BUILD_SHARED_SDK "Build shared library librtc_video_sdk.so with hidden internal symbols" ON)
option(RTC_BUILD_SERVERS    "Build companion P2P WS Signaling and MoQ Relay servers" ON)
option(RTC_BUILD_EXAMPLES   "Build complete C99 and C++17 SDK usage examples" ON)
option(RTC_BUILD_TESTS      "Build unit, weak-network E2E, and example verification tests" ON)

# 1. 核心依赖库：Threads、OpenSSL、Boost、libsrtp2
find_package(Threads REQUIRED)
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Boost 1.70 REQUIRED COMPONENTS system thread)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsrtp/CMakeLists.txt")
  set(ENABLE_OPENSSL ON CACHE BOOL "" FORCE)
  set(LIBSRTP_TEST_APPS OFF CACHE BOOL "" FORCE)
  set(ENABLE_WARNINGS OFF CACHE BOOL "" FORCE)
  set(ENABLE_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  add_subdirectory(third_party/libsrtp EXCLUDE_FROM_ALL)
  set(RTC_SRTP_TARGET srtp2)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SRTP2 REQUIRED IMPORTED_TARGET libsrtp2)
  set(RTC_SRTP_TARGET PkgConfig::SRTP2)
endif()

# 2. 核心 C++17 静态库（Google C++ 代码风格 + 统一日志 + WebRTC P2P + IETF MoQ）
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
  src/moq/moq_transport.cc
  src/call/webrtc_p2p_backend.cc
  src/sdk/rtc_video_engine_impl.cc
)

set(RTC_STRICT_CXX_FLAGS -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Wno-unused-parameter)
set(RTC_STRICT_C_FLAGS   -Wall -Wextra -Wshadow)

add_library(rtc_video_core STATIC ${RTC_CORE_SOURCES})
target_include_directories(rtc_video_core
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_options(rtc_video_core PRIVATE ${RTC_STRICT_CXX_FLAGS})
target_link_libraries(rtc_video_core
  PUBLIC
    Boost::system
    Boost::thread
    OpenSSL::SSL
    OpenSSL::Crypto
    ${RTC_SRTP_TARGET}
    Threads::Threads
)

# 3. 嵌入式 C99 ABI 动态库 SDK（隐藏内部 Boost/OpenSSL/STL 符号）
if(RTC_BUILD_SHARED_SDK)
  add_library(rtc_video_sdk SHARED src/sdk/rtc_video_engine_impl.cc)
  target_include_directories(rtc_video_sdk
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_compile_options(rtc_video_sdk PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_video_sdk PRIVATE rtc_video_core)
  set_target_properties(rtc_video_sdk PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
  )
  if(UNIX AND NOT APPLE)
    target_link_options(rtc_video_sdk PRIVATE
      "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/cmake/rtc_video_sdk.version"
      "-Wl,--exclude-libs,ALL"
    )
  endif()
endif()

# 4. 配套轻量级服务端（零媒体转发 P2P WS 信令服务 + MoQ QUIC 中继服务）
if(RTC_BUILD_SERVERS)
  add_library(rtc_companion_servers STATIC
    src/server/p2p_ws_signaling_server.cc
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

# 5. 全场景 SDK 使用示例（涵盖 P2P 与 MoQ 的纯 C99 及现代 C++17 示例）
if(RTC_BUILD_EXAMPLES AND RTC_BUILD_SERVERS)
  if(RTC_BUILD_SHARED_SDK)
    # 5.1 纯 C99 WebRTC P2P 完整示例（直连 W3C SDP + WS 自动信令）
    add_executable(rtc_example_c99_p2p examples/c99_webrtc_p2p_full_demo.c)
    set_target_properties(rtc_example_c99_p2p PROPERTIES
      C_STANDARD 99
      C_STANDARD_REQUIRED ON
      C_EXTENSIONS OFF
    )
    target_compile_options(rtc_example_c99_p2p PRIVATE ${RTC_STRICT_C_FLAGS})
    target_link_libraries(rtc_example_c99_p2p PRIVATE
      rtc_video_sdk
      Threads::Threads
    )

    # 5.2 纯 C99 IETF MoQ 多路推流与多路拉流完整示例
    add_executable(rtc_example_c99_moq examples/c99_moq_multipull_full_demo.c)
    set_target_properties(rtc_example_c99_moq PROPERTIES
      C_STANDARD 99
      C_STANDARD_REQUIRED ON
      C_EXTENSIONS OFF
    )
    target_compile_options(rtc_example_c99_moq PRIVATE ${RTC_STRICT_C_FLAGS})
    target_link_libraries(rtc_example_c99_moq PRIVATE
      rtc_video_sdk
      Threads::Threads
    )
  endif()

  # 5.3 现代 C++17 WebRTC P2P 完整示例（直连 W3C SDP + WS 自动信令）
  add_executable(rtc_example_cpp17_p2p examples/cpp17_webrtc_p2p_full_demo.cc)
  target_compile_options(rtc_example_cpp17_p2p PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_example_cpp17_p2p PRIVATE
    rtc_companion_servers
    rtc_video_core
  )

  # 5.4 现代 C++17 IETF MoQ 多路推流与多路拉流完整示例
  add_executable(rtc_example_cpp17_moq examples/cpp17_moq_multipull_full_demo.cc)
  target_compile_options(rtc_example_cpp17_moq PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_example_cpp17_moq PRIVATE
    rtc_companion_servers
    rtc_video_core
  )

  # 5.5 浏览器 HTML5 <video> WebRTC P2P HTTP 网关与自测示例
  add_executable(rtc_example_browser_p2p
    examples/browser_webrtc_p2p_gateway_demo.cc
  )
  target_compile_options(rtc_example_browser_p2p PRIVATE ${RTC_STRICT_CXX_FLAGS})
  target_link_libraries(rtc_example_browser_p2p PRIVATE rtc_video_core)
endif()

# 6. 单元测试、弱网端到端（E2E）测试及完整 C99/C++17 示例验证套件
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
    if(TARGET rtc_example_c99_p2p)
      add_test(NAME SdkExampleC99WebRtcP2pFull
        COMMAND rtc_example_c99_p2p
          --sig-bin $<TARGET_FILE:rtc_p2p_ws_signaling_server>
      )
    endif()
    if(TARGET rtc_example_c99_moq)
      add_test(NAME SdkExampleC99MoqMultiPullFull
        COMMAND rtc_example_c99_moq
          --relay-bin $<TARGET_FILE:rtc_moq_relay_server>
      )
    endif()
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
  endif()
endif()
