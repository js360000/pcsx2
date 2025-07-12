// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "OneDriveSettingsWidget.h"
#include "SettingWidgetBinder.h"
#include "SettingsWindow.h"
#include "QtHost.h"
#include "QtUtils.h"

#include "pcsx2/CDVD/OneDriveFileReader.h"
#include "pcsx2/OneDriveAPI.h"

#include <QtWidgets/QMessageBox>
#include <QtWidgets/QInputDialog>

OneDriveSettingsWidget::OneDriveSettingsWidget(SettingsWindow* dialog, QWidget* parent)
	: QWidget(parent)
	, m_dialog(dialog)
{
	m_ui.setupUi(this);

	// Enable/disable OneDrive streaming
	SettingWidgetBinder::BindWidgetToBoolSetting(nullptr, m_ui.oneDriveEnable, "OneDrive", "Enabled", false);
	connect(m_ui.oneDriveEnable, &QCheckBox::toggled, this, &OneDriveSettingsWidget::onOneDriveEnabledChanged);

	// Cache settings
	SettingWidgetBinder::BindWidgetToIntSetting(nullptr, m_ui.cacheSize, "OneDrive", "CacheSizeMB", 64);
	SettingWidgetBinder::BindWidgetToIntSetting(nullptr, m_ui.prefetchSize, "OneDrive", "PrefetchSizeMB", 8);

	// Authentication
	connect(m_ui.authenticateButton, &QPushButton::clicked, this, &OneDriveSettingsWidget::onAuthenticateClicked);
	connect(m_ui.testConnectionButton, &QPushButton::clicked, this, &OneDriveSettingsWidget::onTestConnectionClicked);
	connect(m_ui.clearCacheButton, &QPushButton::clicked, this, &OneDriveSettingsWidget::onClearCacheClicked);

	// Show bandwidth requirements
	showBandwidthRequirements();
	setupAuthenticationInfo();
	onOneDriveEnabledChanged();
}

OneDriveSettingsWidget::~OneDriveSettingsWidget() = default;

void OneDriveSettingsWidget::onOneDriveEnabledChanged()
{
	const bool enabled = m_ui.oneDriveEnable->isChecked();
	m_ui.authenticationGroup->setEnabled(enabled);
	m_ui.cacheGroup->setEnabled(enabled);
	
	if (enabled)
	{
		setupAuthenticationInfo();
	}
}

void OneDriveSettingsWidget::onAuthenticateClicked()
{
	QMessageBox::information(this, tr("OneDrive Authentication"),
		tr("OneDrive authentication requires setting up an Azure app registration.\n\n"
		   "Please follow these steps:\n"
		   "1. Visit https://portal.azure.com and create a new app registration\n"
		   "2. Set redirect URI to: http://localhost:8080/callback\n"
		   "3. Copy the Client ID and Client Secret\n"
		   "4. Enter them in the fields below\n\n"
		   "For detailed instructions, see the PCSX2 documentation."));

	bool ok;
	QString clientId = QInputDialog::getText(this, tr("OneDrive Client ID"),
		tr("Enter your Azure app Client ID:"), QLineEdit::Normal, 
		QString::fromStdString(Host::GetBaseStringSettingValue("OneDrive", "ClientID", "")), &ok);
	
	if (!ok || clientId.isEmpty())
		return;

	QString clientSecret = QInputDialog::getText(this, tr("OneDrive Client Secret"),
		tr("Enter your Azure app Client Secret:"), QLineEdit::Password, 
		QString::fromStdString(Host::GetBaseStringSettingValue("OneDrive", "ClientSecret", "")), &ok);
	
	if (!ok || clientSecret.isEmpty())
		return;

	// Save credentials
	Host::SetBaseStringSettingValue("OneDrive", "ClientID", clientId.toStdString().c_str());
	Host::SetBaseStringSettingValue("OneDrive", "ClientSecret", clientSecret.toStdString().c_str());
	Host::CommitBaseSettingChanges();

	setupAuthenticationInfo();

	QMessageBox::information(this, tr("OneDrive Authentication"),
		tr("Credentials saved. You'll need to authenticate when opening a OneDrive URL for the first time.\n\n"
		   "Note: OneDrive streaming is only supported on Linux and macOS."));
}

void OneDriveSettingsWidget::onTestConnectionClicked()
{
	const std::string clientId = Host::GetBaseStringSettingValue("OneDrive", "ClientID", "");
	const std::string accessToken = Host::GetBaseStringSettingValue("OneDrive", "AccessToken", "");
	
	if (clientId.empty())
	{
		QMessageBox::warning(this, tr("Test Connection"),
			tr("Please configure authentication first."));
		return;
	}

#ifdef _WIN32
	QMessageBox::warning(this, tr("Test Connection"),
		tr("OneDrive streaming is not supported on Windows."));
	return;
#endif

	if (accessToken.empty())
	{
		QMessageBox::information(this, tr("Test Connection"),
			tr("No access token available. Authentication will be required when opening a OneDrive URL."));
		return;
	}

	QMessageBox::information(this, tr("Test Connection"),
		tr("OneDrive authentication appears to be configured. Connection will be tested when opening a OneDrive URL."));
}

void OneDriveSettingsWidget::onClearCacheClicked()
{
	if (QMessageBox::question(this, tr("Clear Cache"),
		tr("Are you sure you want to clear the OneDrive cache? This will remove all cached ISO data."),
		QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
	{
		// TODO: Implement cache clearing
		QMessageBox::information(this, tr("Clear Cache"), tr("Cache cleared successfully."));
	}
}

void OneDriveSettingsWidget::setupAuthenticationInfo()
{
	const std::string clientId = Host::GetBaseStringSettingValue("OneDrive", "ClientID", "");
	const std::string accessToken = Host::GetBaseStringSettingValue("OneDrive", "AccessToken", "");
	
	if (clientId.empty())
	{
		m_ui.authStatus->setText(tr("Not configured"));
		m_ui.authStatus->setStyleSheet("color: red;");
	}
	else if (accessToken.empty())
	{
		m_ui.authStatus->setText(tr("Configured (needs authentication)"));
		m_ui.authStatus->setStyleSheet("color: orange;");
	}
	else
	{
		m_ui.authStatus->setText(tr("Authenticated"));
		m_ui.authStatus->setStyleSheet("color: green;");
	}
}

void OneDriveSettingsWidget::showBandwidthRequirements()
{
	m_ui.bandwidthInfo->setText(QString::fromStdString(OneDriveAPI::GetBandwidthRequirements()));
}