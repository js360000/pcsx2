// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include <QtWidgets/QWidget>

#include "ui_OneDriveSettingsWidget.h"

class SettingsWindow;

class OneDriveSettingsWidget : public QWidget
{
	Q_OBJECT

public:
	OneDriveSettingsWidget(SettingsWindow* dialog, QWidget* parent);
	~OneDriveSettingsWidget();

public Q_SLOTS:
	void onOneDriveEnabledChanged();
	void onAuthenticateClicked();
	void onTestConnectionClicked();
	void onClearCacheClicked();

private:
	void setupAuthenticationInfo();
	void showBandwidthRequirements();

	Ui::OneDriveSettingsWidget m_ui;
	SettingsWindow* m_dialog;
};