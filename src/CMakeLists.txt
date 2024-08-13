# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
add_subdirectory(icons)
add_subdirectory(mimetypes)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if (NOT DISABLE_KWATCHGNUPG)
    add_subdirectory(kwatchgnupg)
endif()
add_subdirectory(libkleopatraclient)
add_subdirectory(conf)

if(WIN32)
  set(_kleopatra_extra_uiserver_SRCS uiserver/uiserver_win.cpp)
  set(_kleopatra_extra_SRCS
      selftest/registrycheck.cpp selftest/registrycheck.h
      utils/gnupg-registry.c
      utils/userinfo_win.cpp
      utils/winapi-helpers.cpp utils/winapi-helpers.h
      utils/windowsprocessdevice.cpp utils/windowsprocessdevice.h
      versioninfo.rc kleopatra.w32-manifest
  )
else()
  set(_kleopatra_extra_uiserver_SRCS uiserver/uiserver_unix.cpp)
  set(_kleopatra_extra_SRCS)
endif()

set(_kleopatra_uiserver_SRCS
    ${_kleopatra_extra_uiserver_SRCS}

    selftest/uiservercheck.cpp selftest/uiservercheck.h
    uiserver/assuanserverconnection.cpp uiserver/assuanserverconnection.h
    uiserver/createchecksumscommand.cpp uiserver/createchecksumscommand.h
    uiserver/decryptverifycommandemailbase.cpp uiserver/decryptverifycommandemailbase.h
    uiserver/decryptverifycommandfilesbase.cpp uiserver/decryptverifycommandfilesbase.h
    uiserver/echocommand.cpp uiserver/echocommand.h
    uiserver/encryptcommand.cpp uiserver/encryptcommand.h
    uiserver/importfilescommand.cpp uiserver/importfilescommand.h
    uiserver/prepencryptcommand.cpp uiserver/prepencryptcommand.h
    uiserver/prepsigncommand.cpp uiserver/prepsigncommand.h
    uiserver/selectcertificatecommand.cpp
    uiserver/sessiondata.cpp uiserver/sessiondata.h
    uiserver/signcommand.cpp uiserver/signcommand.h
    uiserver/signencryptfilescommand.cpp
    uiserver/uiserver.cpp
    uiserver/verifychecksumscommand.cpp uiserver/verifychecksumscommand.h
  )

set(_kleopatra_uiserver_extra_libs LibAssuan::LibAssuan LibGpgError::LibGpgError)

if(HAVE_GPG_ERR_SOURCE_KLEO)
  add_definitions(-DGPG_ERR_SOURCE_DEFAULT=GPG_ERR_SOURCE_KLEO)
  add_definitions(-DGPGMEPP_ERR_SOURCE_DEFAULT=GPG_ERR_SOURCE_KLEO)
else()
  add_definitions(-DGPG_ERR_SOURCE_DEFAULT=GPG_ERR_SOURCE_USER_1)
  add_definitions(-DGPGMEPP_ERR_SOURCE_DEFAULT=GPG_ERR_SOURCE_USER_1)
endif()

if(KPim6IdentityManagementCore_FOUND AND KPim6MailTransport_FOUND AND KPim6AkonadiMime_FOUND)
  set(_kleopatra_mail_libs
      KPim6::IdentityManagementCore # Export OpenPGP keys using WKS
      KPim6::MailTransport
      KPim6::AkonadiMime
  )
  add_definitions(-DMAILAKONADI_ENABLED)
endif()

ki18n_wrap_ui(_kleopatra_uiserver_SRCS crypto/gui/signingcertificateselectionwidget.ui)

set(_kleopatra_SRCS
  ${_kleopatra_extra_SRCS}

  accessibility/accessiblelink.cpp
  accessibility/accessiblelink_p.h
  accessibility/accessiblerichtextlabel.cpp
  accessibility/accessiblerichtextlabel_p.h
  accessibility/accessiblevaluelabel.cpp
  accessibility/accessiblevaluelabel_p.h
  accessibility/accessiblewidgetfactory.cpp
  accessibility/accessiblewidgetfactory.h
  commands/addadskcommand.cpp
  commands/addadskcommand.h
  commands/addsubkeycommand.cpp
  commands/addsubkeycommand.h
  commands/adduseridcommand.cpp
  commands/adduseridcommand.h
  commands/authenticatepivcardapplicationcommand.cpp
  commands/authenticatepivcardapplicationcommand.h
  commands/cardcommand.cpp
  commands/cardcommand.h
  commands/certificatetocardcommand.cpp
  commands/certificatetocardcommand.h
  commands/certificatetopivcardcommand.cpp
  commands/certificatetopivcardcommand.h
  commands/certifycertificatecommand.cpp
  commands/certifycertificatecommand.h
  commands/certifygroupcommand.cpp
  commands/certifygroupcommand.h
  commands/changeexpirycommand.cpp
  commands/changeexpirycommand.h
  commands/changeownertrustcommand.cpp
  commands/changeownertrustcommand.h
  commands/changepassphrasecommand.cpp
  commands/changepassphrasecommand.h
  commands/changepincommand.cpp
  commands/changepincommand.h
  commands/changeroottrustcommand.cpp
  commands/changeroottrustcommand.h
  commands/checksumcreatefilescommand.cpp
  commands/checksumcreatefilescommand.h
  commands/checksumverifyfilescommand.cpp
  commands/checksumverifyfilescommand.h
  commands/clearcrlcachecommand.cpp
  commands/clearcrlcachecommand.h
  commands/command.cpp
  commands/command.h
  commands/createcsrforcardkeycommand.cpp
  commands/createcsrforcardkeycommand.h
  commands/creategroupcommand.cpp
  commands/creategroupcommand.h
  commands/createopenpgpkeyfromcardkeyscommand.cpp
  commands/createopenpgpkeyfromcardkeyscommand.h
  commands/decryptverifyclipboardcommand.cpp
  commands/decryptverifyclipboardcommand.h
  commands/decryptverifyfilescommand.cpp
  commands/decryptverifyfilescommand.h
  commands/deletecertificatescommand.cpp
  commands/deletecertificatescommand.h
  commands/detailscommand.cpp
  commands/detailscommand.h
  commands/dumpcertificatecommand.cpp
  commands/dumpcertificatecommand.h
  commands/dumpcrlcachecommand.cpp
  commands/dumpcrlcachecommand.h
  commands/encryptclipboardcommand.cpp
  commands/encryptclipboardcommand.h
  commands/exportcertificatecommand.cpp
  commands/exportcertificatecommand.h
  commands/exportgroupscommand.cpp
  commands/exportgroupscommand.h
  commands/exportopenpgpcertstoservercommand.cpp
  commands/exportopenpgpcertstoservercommand.h
  commands/exportopenpgpcerttoprovidercommand.cpp
  commands/exportopenpgpcerttoprovidercommand.h
  commands/exportpaperkeycommand.cpp
  commands/exportpaperkeycommand.h
  commands/exportsecretkeycommand.cpp
  commands/exportsecretkeycommand.h
  commands/exportsecretsubkeycommand.cpp
  commands/exportsecretsubkeycommand.h
  commands/genrevokecommand.cpp
  commands/genrevokecommand.h
  commands/gnupgprocesscommand.cpp
  commands/gnupgprocesscommand.h
  commands/importcertificatefromclipboardcommand.cpp
  commands/importcertificatefromclipboardcommand.h
  commands/importcertificatefromdatacommand.cpp
  commands/importcertificatefromdatacommand.h
  commands/importcertificatefromfilecommand.cpp
  commands/importcertificatefromfilecommand.h
  commands/importcertificatefromkeyservercommand.cpp
  commands/importcertificatefromkeyservercommand.h
  commands/importcertificatefrompivcardcommand.cpp
  commands/importcertificatefrompivcardcommand.h
  commands/importcertificatescommand.cpp
  commands/importcertificatescommand.h
  commands/importcrlcommand.cpp
  commands/importcrlcommand.h
  commands/importpaperkeycommand.cpp
  commands/importpaperkeycommand.h
  commands/keytocardcommand.cpp
  commands/keytocardcommand.h
  commands/lookupcertificatescommand.cpp
  commands/lookupcertificatescommand.h
  commands/newcertificatesigningrequestcommand.cpp
  commands/newcertificatesigningrequestcommand.h
  commands/newopenpgpcertificatecommand.cpp
  commands/newopenpgpcertificatecommand.h
  commands/openpgpgeneratecardkeycommand.cpp
  commands/openpgpgeneratecardkeycommand.h
  commands/pivgeneratecardkeycommand.cpp
  commands/pivgeneratecardkeycommand.h
  commands/refreshcertificatescommand.cpp
  commands/refreshcertificatescommand.h
  commands/refreshopenpgpcertscommand.cpp
  commands/refreshopenpgpcertscommand.h
  commands/refreshx509certscommand.cpp
  commands/refreshx509certscommand.h
  commands/reloadkeyscommand.cpp
  commands/reloadkeyscommand.h
  commands/revokecertificationcommand.cpp
  commands/revokecertificationcommand.h
  commands/revokekeycommand.cpp
  commands/revokekeycommand.h
  commands/revokeuseridcommand.cpp
  commands/revokeuseridcommand.h
  commands/selftestcommand.cpp
  commands/selftestcommand.h
  commands/setinitialpincommand.cpp
  commands/setinitialpincommand.h
  commands/setpivcardapplicationadministrationkeycommand.cpp
  commands/setpivcardapplicationadministrationkeycommand.h
  commands/setprimaryuseridcommand.cpp
  commands/setprimaryuseridcommand.h
  commands/signclipboardcommand.cpp
  commands/signclipboardcommand.h
  commands/signencryptfilescommand.cpp
  commands/signencryptfilescommand.h
  commands/signencryptfoldercommand.cpp
  commands/signencryptfoldercommand.h
  commands/togglecertificateenabledcommand.cpp
  commands/togglecertificateenabledcommand.h
  commands/viewemailfilescommand.cpp
  commands/viewemailfilescommand.h
  conf/configuredialog.cpp
  conf/configuredialog.h
  conf/groupsconfigdialog.cpp
  conf/groupsconfigdialog.h
  conf/groupsconfigwidget.cpp
  conf/groupsconfigwidget.h
  crypto/autodecryptverifyfilescontroller.cpp
  crypto/autodecryptverifyfilescontroller.h
  crypto/certificateresolver.cpp
  crypto/certificateresolver.h
  crypto/checksumsutils_p.cpp
  crypto/checksumsutils_p.h
  crypto/controller.cpp
  crypto/controller.h
  crypto/createchecksumscontroller.cpp
  crypto/createchecksumscontroller.h
  crypto/decryptverifyemailcontroller.cpp
  crypto/decryptverifyemailcontroller.h
  crypto/decryptverifyfilescontroller.cpp
  crypto/decryptverifyfilescontroller.h
  crypto/decryptverifytask.cpp
  crypto/decryptverifytask.h
  crypto/encryptemailcontroller.cpp
  crypto/encryptemailcontroller.h
  crypto/encryptemailtask.cpp
  crypto/encryptemailtask.h
  crypto/gui/certificatelineedit.cpp
  crypto/gui/certificatelineedit.h
  crypto/gui/certificateselectionline.cpp
  crypto/gui/certificateselectionline.h
  crypto/gui/decryptverifyfilesdialog.cpp
  crypto/gui/decryptverifyfilesdialog.h
  crypto/gui/decryptverifyfileswizard.cpp
  crypto/gui/decryptverifyfileswizard.h
  crypto/gui/decryptverifyoperationwidget.cpp
  crypto/gui/decryptverifyoperationwidget.h
  crypto/gui/encryptemailwizard.cpp
  crypto/gui/encryptemailwizard.h
  crypto/gui/newresultpage.cpp
  crypto/gui/newresultpage.h
  crypto/gui/objectspage.cpp
  crypto/gui/objectspage.h
  crypto/gui/resolverecipientspage.cpp
  crypto/gui/resolverecipientspage.h
  crypto/gui/resultitemwidget.cpp
  crypto/gui/resultitemwidget.h
  crypto/gui/resultlistwidget.cpp
  crypto/gui/resultlistwidget.h
  crypto/gui/resultpage.cpp
  crypto/gui/resultpage.h
  crypto/gui/signemailwizard.cpp
  crypto/gui/signemailwizard.h
  crypto/gui/signencryptemailconflictdialog.cpp
  crypto/gui/signencryptemailconflictdialog.h
  crypto/gui/signencryptfileswizard.cpp
  crypto/gui/signencryptfileswizard.h
  crypto/gui/signencryptwidget.cpp
  crypto/gui/signencryptwidget.h
  crypto/gui/signencryptwizard.cpp
  crypto/gui/signencryptwizard.h
  crypto/gui/signerresolvepage.cpp
  crypto/gui/signerresolvepage.h
  crypto/gui/signingcertificateselectiondialog.cpp
  crypto/gui/signingcertificateselectiondialog.h
  crypto/gui/signingcertificateselectionwidget.cpp
  crypto/gui/signingcertificateselectionwidget.h
  crypto/gui/unknownrecipientwidget.cpp
  crypto/gui/unknownrecipientwidget.h
  crypto/gui/verifychecksumsdialog.cpp
  crypto/gui/verifychecksumsdialog.h
  crypto/gui/wizard.cpp
  crypto/gui/wizard.h
  crypto/gui/wizardpage.cpp
  crypto/gui/wizardpage.h
  crypto/newsignencryptemailcontroller.cpp
  crypto/newsignencryptemailcontroller.h
  crypto/recipient.cpp
  crypto/recipient.h
  crypto/sender.cpp
  crypto/sender.h
  crypto/signemailcontroller.cpp
  crypto/signemailcontroller.h
  crypto/signemailtask.cpp
  crypto/signemailtask.h
  crypto/signencryptfilescontroller.cpp
  crypto/signencryptfilescontroller.h
  crypto/signencrypttask.cpp
  crypto/signencrypttask.h
  crypto/task.cpp
  crypto/task.h
  crypto/taskcollection.cpp
  crypto/taskcollection.h
  crypto/verifychecksumscontroller.cpp
  crypto/verifychecksumscontroller.h
  dialogs/addsubkeydialog.cpp
  dialogs/addsubkeydialog.h
  dialogs/adduseriddialog.cpp
  dialogs/adduseriddialog.h
  dialogs/animatedexpander.cpp
  dialogs/animatedexpander.h
  dialogs/certificatedetailsdialog.cpp
  dialogs/certificatedetailsdialog.h
  dialogs/certificatedetailsinputwidget.cpp
  dialogs/certificatedetailsinputwidget.h
  dialogs/certificatedetailswidget.cpp
  dialogs/certificatedetailswidget.h
  dialogs/certificatedumpwidget.cpp
  dialogs/certificatedumpwidget.h
  dialogs/certificateselectiondialog.cpp
  dialogs/certificateselectiondialog.h
  dialogs/certifycertificatedialog.cpp
  dialogs/certifycertificatedialog.h
  dialogs/certifywidget.cpp
  dialogs/certifywidget.h
  dialogs/createcsrforcardkeydialog.cpp
  dialogs/createcsrforcardkeydialog.h
  dialogs/copytosmartcarddialog.cpp
  dialogs/copytosmartcarddialog.h
  dialogs/debugdialog.cpp
  dialogs/debugdialog.h
  dialogs/deletecertificatesdialog.cpp
  dialogs/deletecertificatesdialog.h
  dialogs/editgroupdialog.cpp
  dialogs/editgroupdialog.h
  dialogs/expirydialog.cpp
  dialogs/expirydialog.h
  dialogs/exportdialog.cpp
  dialogs/exportdialog.h
  dialogs/gencardkeydialog.cpp
  dialogs/gencardkeydialog.h
  dialogs/groupdetailsdialog.cpp
  dialogs/groupdetailsdialog.h
  dialogs/lookupcertificatesdialog.cpp
  dialogs/lookupcertificatesdialog.h
  dialogs/pivcardapplicationadministrationkeyinputdialog.cpp
  dialogs/pivcardapplicationadministrationkeyinputdialog.h
  dialogs/revokekeydialog.cpp
  dialogs/revokekeydialog.h
  dialogs/revokerswidget.cpp
  dialogs/revokerswidget.h
  dialogs/selftestdialog.cpp
  dialogs/selftestdialog.h
  dialogs/setinitialpindialog.cpp
  dialogs/setinitialpindialog.h
  dialogs/smartcardwindow.cpp
  dialogs/smartcardwindow.h
  dialogs/subkeyswidget.cpp
  dialogs/subkeyswidget.h
  dialogs/trustchainwidget.cpp
  dialogs/trustchainwidget.h
  dialogs/updatenotification.cpp
  dialogs/updatenotification.h
  dialogs/useridswidget.cpp
  dialogs/useridswidget.h
  dialogs/weboftrustwidget.cpp
  dialogs/weboftrustwidget.h
  interfaces/anchorprovider.h
  interfaces/focusfirstchild.h
  newcertificatewizard/advancedsettingsdialog.cpp
  newcertificatewizard/advancedsettingsdialog_p.h
  newcertificatewizard/enterdetailspage.cpp
  newcertificatewizard/enterdetailspage_p.h
  newcertificatewizard/keycreationpage.cpp
  newcertificatewizard/keycreationpage_p.h
  newcertificatewizard/listwidget.cpp
  newcertificatewizard/listwidget.h
  newcertificatewizard/newcertificatewizard.cpp
  newcertificatewizard/newcertificatewizard.h
  newcertificatewizard/resultpage.cpp
  newcertificatewizard/resultpage_p.h
  newcertificatewizard/wizardpage.cpp
  newcertificatewizard/wizardpage_p.h
  selftest/compliancecheck.cpp
  selftest/compliancecheck.h
  selftest/enginecheck.cpp
  selftest/enginecheck.h
  selftest/gpgagentcheck.cpp
  selftest/gpgagentcheck.h
  selftest/gpgconfcheck.cpp
  selftest/gpgconfcheck.h
  selftest/libkleopatrarccheck.cpp
  selftest/libkleopatrarccheck.h
  selftest/selftest.cpp
  selftest/selftest.h
  smartcard/algorithminfo.h
  smartcard/card.cpp
  smartcard/card.h
  smartcard/deviceinfowatcher.cpp
  smartcard/deviceinfowatcher.h
  smartcard/keypairinfo.cpp
  smartcard/keypairinfo.h
  smartcard/netkeycard.cpp
  smartcard/netkeycard.h
  smartcard/openpgpcard.cpp
  smartcard/openpgpcard.h
  smartcard/p15card.cpp
  smartcard/p15card.h
  smartcard/pivcard.cpp
  smartcard/pivcard.h
  smartcard/readerstatus.cpp
  smartcard/readerstatus.h
  smartcard/utils.cpp
  smartcard/utils.h
  utils/accessibility.cpp
  utils/accessibility.h
  utils/action_data.cpp
  utils/action_data.h
  utils/applicationstate.cpp
  utils/applicationstate.h
  utils/archivedefinition.cpp
  utils/archivedefinition.h
  utils/certificatepair.h
  utils/clipboardmenu.cpp
  utils/clipboardmenu.h
  utils/debug-helpers.cpp
  utils/debug-helpers.h
  utils/dragqueen.cpp
  utils/dragqueen.h
  utils/email.cpp
  utils/email.h
  utils/emptypassphraseprovider.cpp
  utils/emptypassphraseprovider.h
  utils/filedialog.cpp
  utils/filedialog.h
  utils/gui-helper.cpp
  utils/gui-helper.h
  utils/headerview.cpp
  utils/headerview.h
  utils/input.cpp
  utils/input.h
  utils/iodevicelogger.cpp
  utils/iodevicelogger.h
  utils/kdpipeiodevice.cpp
  utils/kdpipeiodevice.h
  utils/keyexportdraghandler.cpp
  utils/keyexportdraghandler.h
  utils/kuniqueservice.cpp
  utils/kuniqueservice.h
  utils/log.cpp
  utils/log.h
  utils/memory-helpers.h
  utils/migration.cpp
  utils/migration.h
  utils/output.cpp
  utils/output.h
  utils/overwritedialog.cpp
  utils/overwritedialog.h
  utils/path-helper.cpp
  utils/path-helper.h
  utils/scrollarea.cpp
  utils/scrollarea.h
  utils/systemtrayicon.cpp
  utils/systemtrayicon.h
  utils/tags.cpp
  utils/tags.h
  utils/types.cpp
  utils/types.h
  utils/userinfo.cpp
  utils/userinfo.h
  utils/writecertassuantransaction.cpp
  utils/writecertassuantransaction.h
  utils/wsastarter.cpp
  utils/wsastarter.h
  view/anchorcache.cpp
  view/anchorcache_p.h
  view/cardkeysview.cpp
  view/cardkeysview.h
  view/htmllabel.cpp
  view/htmllabel.h
  view/infofield.cpp
  view/infofield.h
  view/keycacheoverlay.cpp
  view/keycacheoverlay.h
  view/keylistcontroller.cpp
  view/keylistcontroller.h
  view/keytreeview.cpp
  view/keytreeview.h
  view/netkeywidget.cpp
  view/netkeywidget.h
  view/nullpinwidget.cpp
  view/nullpinwidget.h
  view/overlaywidget.cpp
  view/overlaywidget.h
  view/p15cardwidget.cpp
  view/p15cardwidget.h
  view/padwidget.cpp
  view/padwidget.h
  view/pgpcardwidget.cpp
  view/pgpcardwidget.h
  view/pivcardwidget.cpp
  view/pivcardwidget.h
  view/progressoverlay.cpp
  view/progressoverlay.h
  view/searchbar.cpp
  view/searchbar.h
  view/smartcardactions.cpp
  view/smartcardactions.h
  view/smartcardswidget.cpp
  view/smartcardswidget.h
  view/smartcardwidget.cpp
  view/smartcardwidget.h
  view/tabwidget.cpp
  view/tabwidget.h
  view/textoverlay.cpp
  view/textoverlay.h
  view/urllabel.cpp
  view/urllabel.h
  view/waitwidget.cpp
  view/waitwidget.h
  view/welcomewidget.cpp
  view/welcomewidget.h

  aboutdata.cpp
  aboutdata.h
  kleopatra.qrc
  kleopatraapplication.cpp
  kleopatraapplication.h
  main.cpp
  mainwindow.cpp
  mainwindow.h
  systrayicon.cpp
  systrayicon.h
  kleopatra_options.h
)

if(WIN32)
  configure_file (versioninfo.rc.in versioninfo.rc)
  configure_file (kleopatra.w32-manifest.in kleopatra.w32-manifest)
  set(_kleopatra_SRCS
    ${CMAKE_CURRENT_BINARY_DIR}/kleopatra.w32-manifest
    ${CMAKE_CURRENT_BINARY_DIR}/versioninfo.rc
    conf/kmessageboxdontaskagainstorage.cpp
    conf/kmessageboxdontaskagainstorage.h
    ${_kleopatra_SRCS}
  )
endif()

set (_kleopatra_SRCS conf/kleopageconfigdialog.cpp conf/kleopageconfigdialog.h ${_kleopatra_SRCS})

ecm_qt_declare_logging_category(_kleopatra_SRCS HEADER kleopatra_debug.h IDENTIFIER KLEOPATRA_LOG CATEGORY_NAME org.kde.pim.kleopatra
        DESCRIPTION "kleopatra (kleopatra)"
        OLD_CATEGORY_NAMES log_kleopatra
        EXPORT KLEOPATRA
    )


if(KLEO_MODEL_TEST)
  add_definitions(-DKLEO_MODEL_TEST)
  set(_kleopatra_SRCS ${_kleopatra_SRCS} models/modeltest.cpp)
endif()

ki18n_wrap_ui(_kleopatra_SRCS
  dialogs/setinitialpindialog.ui
  newcertificatewizard/listwidget.ui
)

kconfig_add_kcfg_files(_kleopatra_SRCS
  kcfg/emailoperationspreferences.kcfgc
  kcfg/fileoperationspreferences.kcfgc
  kcfg/settings.kcfgc
  kcfg/smimevalidationpreferences.kcfgc
  kcfg/tooltippreferences.kcfgc
)

file(GLOB ICONS_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/icons/*-apps-kleopatra.png")
ecm_add_app_icon(_kleopatra_SRCS ICONS ${ICONS_SRCS})

add_executable(kleopatra_bin ${_kleopatra_SRCS} ${_kleopatra_uiserver_SRCS})

# For the ConfigureDialog & KCMs
target_link_libraries(kleopatra_bin kcm_kleopatra_static)

#if (COMPILE_WITH_UNITY_CMAKE_SUPPORT)
#    set_target_properties(kleopatra_bin PROPERTIES UNITY_BUILD ON)
#endif()
set_target_properties(kleopatra_bin PROPERTIES OUTPUT_NAME kleopatra)

if (WIN32)
  set(_kleopatra_platform_libs "secur32")
endif ()

target_link_libraries(kleopatra_bin
  Gpgmepp
  KPim6::Libkleo
  KPim6::Mime
  KPim6::MimeTreeParserWidgets
  KF6::Codecs
  KF6::CoreAddons
  KF6::Crash
  KF6::I18n
  KF6::IconThemes
  KF6::ItemModels
  KF6::KIOCore
  KF6::KIOWidgets
  KF6::WindowSystem
  KF6::XmlGui
  Qt::Network
  Qt::PrintSupport # Printing secret keys
  kleopatraclientcore
  ${_kleopatra_extra_libs}
  ${_kleopatra_mail_libs}
  ${_kleopatra_uiserver_extra_libs}
  ${_kleopatra_dbusaddons_libs}
  ${_kleopatra_platform_libs}
)

target_link_libraries(kleopatra_bin QGpgmeQt6)

install(TARGETS kleopatra_bin ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})

install(
  PROGRAMS data/org.kde.kleopatra.desktop data/kleopatra_import.desktop
  DESTINATION ${KDE_INSTALL_APPDIR}
)
install(FILES data/org.kde.kleopatra.appdata.xml DESTINATION ${KDE_INSTALL_METAINFODIR})
install(FILES data/kleopatra-mime.xml DESTINATION ${KDE_INSTALL_MIMEDIR})
install(
  PROGRAMS data/kleopatra_signencryptfiles.desktop
        data/kleopatra_signencryptfolders.desktop
        data/kleopatra_decryptverifyfiles.desktop
        data/kleopatra_decryptverifyfolders.desktop
  DESTINATION ${KDE_INSTALL_DATADIR}/kio/servicemenus
)
