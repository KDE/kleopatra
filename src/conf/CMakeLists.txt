include_directories(${kleopatra_SOURCE_DIR}/src)


set(_kcm_kleopatra_libkleopatraclient_extra_SRCS
  smimevalidationconfigurationwidget.cpp
  smimevalidationconfigurationpage.cpp
  cryptooperationsconfigwidget.cpp
  cryptooperationsconfigpage.cpp
  smimevalidationconfigurationwidget.h
  smimevalidationconfigurationpage.h
  cryptooperationsconfigwidget.h
  cryptooperationsconfigpage.h
  smartcardconfigpage.cpp
  smartcardconfigpage.h
)

ki18n_wrap_ui(_kcm_kleopatra_libkleopatraclient_extra_SRCS
  smimevalidationconfigurationwidget.ui
)

kconfig_add_kcfg_files(_kcm_kleopatra_libkleopatraclient_extra_SRCS
  ${kleopatra_SOURCE_DIR}/src/kcfg/smimevalidationpreferences.kcfgc
)

set(_kcm_kleopatra_libkleopatraclient_extra_LIBS kleopatraclientgui)


set(kcm_kleopatra_PART_SRCS
  dirservconfigpage.cpp
  appearanceconfigpage.cpp
  appearanceconfigwidget.cpp
  gnupgsystemconfigurationpage.cpp
  dirservconfigpage.h
  appearanceconfigpage.h
  appearanceconfigwidget.h
  gnupgsystemconfigurationpage.h
  labelledwidget.cpp labelledwidget.h
  labelledwidget.cpp labelledwidget.h
  pluralhandlingspinbox.cpp
  pluralhandlingspinbox.h
  kleoconfigmodule.cpp
  kleoconfigmodule.h
  ${kleopatra_BINARY_DIR}/src/kleopatra_debug.cpp
  ${_kcm_kleopatra_libkleopatraclient_extra_SRCS}
)


ki18n_wrap_ui(kcm_kleopatra_PART_SRCS
  smimevalidationconfigurationwidget.ui
)

kconfig_add_kcfg_files(kcm_kleopatra_PART_SRCS
  ${kleopatra_SOURCE_DIR}/src/kcfg/tooltippreferences.kcfgc
  ${kleopatra_SOURCE_DIR}/src/kcfg/settings.kcfgc
)

add_library(kcm_kleopatra_static STATIC ${kcm_kleopatra_PART_SRCS})
set_property(TARGET kcm_kleopatra_static PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(kcm_kleopatra_static
  KPim${KF_MAJOR_VERSION}::Libkleo
  KF${KF_MAJOR_VERSION}::ConfigCore
  KF${KF_MAJOR_VERSION}::ConfigWidgets
  KF${KF_MAJOR_VERSION}::I18n
  KF${KF_MAJOR_VERSION}::IconThemes
  KF${KF_MAJOR_VERSION}::WidgetsAddons
  ${_kcm_kleopatra_extra_libs}
  ${_kleopatra_dbusaddons_libs}
  ${_kcm_kleopatra_libkleopatraclient_extra_LIBS}
)
