package im.uwrkaxlmjj.ui;

import android.animation.AnimatorSet;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.NotificationsCheckCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
@Deprecated
public class DataSettingsActivity extends BaseFragment {
    private AnimatorSet animatorSet;
    private int autoplayGifsRow;
    private int autoplayHeaderRow;
    private int autoplaySectionRow;
    private int autoplayVideoRow;
    private int callsSection2Row;
    private int callsSectionRow;
    private int dataUsageRow;
    private int enableAllStreamInfoRow;
    private int enableAllStreamRow;
    private int enableCacheStreamRow;
    private int enableMkvRow;
    private int enableStreamRow;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private int mediaDownloadSection2Row;
    private int mediaDownloadSectionRow;
    private int mobileRow;
    private int proxyRow;
    private int proxySection2Row;
    private int proxySectionRow;
    private int quickRepliesRow;
    private int resetDownloadRow;
    private int roamingRow;
    private int rowCount;
    private int storageUsageRow;
    private int streamSectionRow;
    private int usageSection2Row;
    private int usageSectionRow;
    private int useLessDataForCallsRow;
    private int wifiRow;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        DownloadController.getInstance(this.currentAccount).loadAutoDownloadConfig(true);
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.usageSectionRow = 0;
        int i2 = i + 1;
        this.rowCount = i2;
        this.storageUsageRow = i;
        int i3 = i2 + 1;
        this.rowCount = i3;
        this.dataUsageRow = i2;
        int i4 = i3 + 1;
        this.rowCount = i4;
        this.usageSection2Row = i3;
        int i5 = i4 + 1;
        this.rowCount = i5;
        this.mediaDownloadSectionRow = i4;
        int i6 = i5 + 1;
        this.rowCount = i6;
        this.mobileRow = i5;
        int i7 = i6 + 1;
        this.rowCount = i7;
        this.wifiRow = i6;
        int i8 = i7 + 1;
        this.rowCount = i8;
        this.roamingRow = i7;
        int i9 = i8 + 1;
        this.rowCount = i9;
        this.resetDownloadRow = i8;
        int i10 = i9 + 1;
        this.rowCount = i10;
        this.mediaDownloadSection2Row = i9;
        int i11 = i10 + 1;
        this.rowCount = i11;
        this.autoplayHeaderRow = i10;
        int i12 = i11 + 1;
        this.rowCount = i12;
        this.autoplayGifsRow = i11;
        int i13 = i12 + 1;
        this.rowCount = i13;
        this.autoplayVideoRow = i12;
        int i14 = i13 + 1;
        this.rowCount = i14;
        this.autoplaySectionRow = i13;
        int i15 = i14 + 1;
        this.rowCount = i15;
        this.streamSectionRow = i14;
        this.rowCount = i15 + 1;
        this.enableStreamRow = i15;
        if (BuildVars.DEBUG_VERSION) {
            int i16 = this.rowCount;
            int i17 = i16 + 1;
            this.rowCount = i17;
            this.enableMkvRow = i16;
            this.rowCount = i17 + 1;
            this.enableAllStreamRow = i17;
        } else {
            this.enableAllStreamRow = -1;
            this.enableMkvRow = -1;
        }
        int i18 = this.rowCount;
        int i19 = i18 + 1;
        this.rowCount = i19;
        this.enableAllStreamInfoRow = i18;
        this.enableCacheStreamRow = -1;
        int i20 = i19 + 1;
        this.rowCount = i20;
        this.callsSectionRow = i19;
        int i21 = i20 + 1;
        this.rowCount = i21;
        this.useLessDataForCallsRow = i20;
        int i22 = i21 + 1;
        this.rowCount = i22;
        this.quickRepliesRow = i21;
        int i23 = i22 + 1;
        this.rowCount = i23;
        this.callsSection2Row = i22;
        int i24 = i23 + 1;
        this.rowCount = i24;
        this.proxySectionRow = i23;
        int i25 = i24 + 1;
        this.rowCount = i25;
        this.proxyRow = i24;
        this.rowCount = i25 + 1;
        this.proxySection2Row = i25;
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString("DataSettings", R.string.DataSettings));
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.DataSettingsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    DataSettingsActivity.this.finishFragment();
                }
            }
        });
        this.listAdapter = new ListAdapter(context);
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, 51));
        this.listView.setAdapter(this.listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListenerExtended() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DataSettingsActivity$pekyhYfiIHNmNzxXbf47t2dNt4U
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListenerExtended
            public final void onItemClick(View view, int i, float f, float f2) {
                this.f$0.lambda$createView$2$DataSettingsActivity(view, i, f, f2);
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$2$DataSettingsActivity(View view, final int position, float x, float y) {
        int type;
        DownloadController.Preset preset;
        DownloadController.Preset defaultPreset;
        String key;
        String key2;
        int num;
        if (position == this.mobileRow || position == this.roamingRow || position == this.wifiRow) {
            if ((LocaleController.isRTL && x <= AndroidUtilities.dp(76.0f)) || (!LocaleController.isRTL && x >= view.getMeasuredWidth() - AndroidUtilities.dp(76.0f))) {
                boolean wasEnabled = this.listAdapter.isRowEnabled(this.resetDownloadRow);
                NotificationsCheckCell cell = (NotificationsCheckCell) view;
                boolean checked = cell.isChecked();
                if (position == this.mobileRow) {
                    preset = DownloadController.getInstance(this.currentAccount).mobilePreset;
                    defaultPreset = DownloadController.getInstance(this.currentAccount).mediumPreset;
                    key = "mobilePreset";
                    key2 = "currentMobilePreset";
                    num = 0;
                } else if (position == this.wifiRow) {
                    preset = DownloadController.getInstance(this.currentAccount).wifiPreset;
                    defaultPreset = DownloadController.getInstance(this.currentAccount).highPreset;
                    key = "wifiPreset";
                    key2 = "currentWifiPreset";
                    num = 1;
                } else {
                    preset = DownloadController.getInstance(this.currentAccount).roamingPreset;
                    defaultPreset = DownloadController.getInstance(this.currentAccount).lowPreset;
                    key = "roamingPreset";
                    key2 = "currentRoamingPreset";
                    num = 2;
                }
                if (!checked && preset.enabled) {
                    preset.set(defaultPreset);
                } else {
                    preset.enabled = true ^ preset.enabled;
                }
                SharedPreferences.Editor editor = MessagesController.getMainSettings(this.currentAccount).edit();
                editor.putString(key, preset.toString());
                editor.putInt(key2, 3);
                editor.commit();
                cell.setChecked(!checked);
                RecyclerView.ViewHolder holder = this.listView.findContainingViewHolder(view);
                if (holder != null) {
                    this.listAdapter.onBindViewHolder(holder, position);
                }
                DownloadController.getInstance(this.currentAccount).checkAutodownloadSettings();
                DownloadController.getInstance(this.currentAccount).savePresetToServer(num);
                if (wasEnabled != this.listAdapter.isRowEnabled(this.resetDownloadRow)) {
                    this.listAdapter.notifyItemChanged(this.resetDownloadRow);
                    return;
                }
                return;
            }
            if (position == this.mobileRow) {
                type = 0;
            } else {
                int type2 = this.wifiRow;
                if (position == type2) {
                    type = 1;
                } else {
                    type = 2;
                }
            }
            presentFragment(new DataAutoDownloadActivity(type));
            return;
        }
        if (position == this.resetDownloadRow) {
            if (getParentActivity() == null || !view.isEnabled()) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("ResetAutomaticMediaDownloadAlertTitle", R.string.ResetAutomaticMediaDownloadAlertTitle));
            builder.setMessage(LocaleController.getString("ResetAutomaticMediaDownloadAlert", R.string.ResetAutomaticMediaDownloadAlert));
            builder.setPositiveButton(LocaleController.getString("Reset", R.string.Reset), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DataSettingsActivity$jrxunwlGyDMECN4c0-DOEu4ZsU8
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$0$DataSettingsActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            AlertDialog dialog = builder.create();
            showDialog(dialog);
            TextView button = (TextView) dialog.getButton(-1);
            if (button != null) {
                button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
                return;
            }
            return;
        }
        if (position == this.storageUsageRow) {
            presentFragment(new CacheControlActivity());
            return;
        }
        if (position != this.useLessDataForCallsRow) {
            if (position == this.dataUsageRow) {
                presentFragment(new DataUsageActivity());
                return;
            }
            if (position == this.proxyRow) {
                presentFragment(new ProxyListActivity());
                return;
            }
            if (position != this.enableStreamRow) {
                if (position != this.enableAllStreamRow) {
                    if (position != this.enableMkvRow) {
                        if (position != this.enableCacheStreamRow) {
                            if (position == this.quickRepliesRow) {
                                presentFragment(new QuickRepliesSettingsActivity());
                                return;
                            }
                            if (position == this.autoplayGifsRow) {
                                SharedConfig.toggleAutoplayGifs();
                                if (view instanceof TextCheckCell) {
                                    ((TextCheckCell) view).setChecked(SharedConfig.autoplayGifs);
                                    return;
                                }
                                return;
                            }
                            if (position == this.autoplayVideoRow) {
                                SharedConfig.toggleAutoplayVideo();
                                if (view instanceof TextCheckCell) {
                                    ((TextCheckCell) view).setChecked(SharedConfig.autoplayVideo);
                                    return;
                                }
                                return;
                            }
                            return;
                        }
                        SharedConfig.toggleSaveStreamMedia();
                        TextCheckCell textCheckCell = (TextCheckCell) view;
                        textCheckCell.setChecked(SharedConfig.saveStreamMedia);
                        return;
                    }
                    SharedConfig.toggleStreamMkv();
                    TextCheckCell textCheckCell2 = (TextCheckCell) view;
                    textCheckCell2.setChecked(SharedConfig.streamMkv);
                    return;
                }
                SharedConfig.toggleStreamAllVideo();
                TextCheckCell textCheckCell3 = (TextCheckCell) view;
                textCheckCell3.setChecked(SharedConfig.streamAllVideo);
                return;
            }
            SharedConfig.toggleStreamMedia();
            TextCheckCell textCheckCell4 = (TextCheckCell) view;
            textCheckCell4.setChecked(SharedConfig.streamMedia);
            return;
        }
        final SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        int selected = 0;
        int i = preferences.getInt("VoipDataSaving", VoIPHelper.getDataSavingDefault());
        if (i == 0) {
            selected = 0;
        } else if (i == 1) {
            selected = 2;
        } else if (i == 2) {
            selected = 3;
        } else if (i == 3) {
            selected = 1;
        }
        Dialog dlg = AlertsCreator.createSingleChoiceDialog(getParentActivity(), new String[]{LocaleController.getString("UseLessDataNever", R.string.UseLessDataNever), LocaleController.getString("UseLessDataOnRoaming", R.string.UseLessDataOnRoaming), LocaleController.getString("UseLessDataOnMobile", R.string.UseLessDataOnMobile), LocaleController.getString("UseLessDataAlways", R.string.UseLessDataAlways)}, LocaleController.getString("VoipUseLessData", R.string.VoipUseLessData), selected, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DataSettingsActivity$HjCqh3mYzvwTOSzK4kfyxWvA9CE
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i2) {
                this.f$0.lambda$null$1$DataSettingsActivity(preferences, position, dialogInterface, i2);
            }
        });
        setVisibleDialog(dlg);
        dlg.show();
    }

    public /* synthetic */ void lambda$null$0$DataSettingsActivity(DialogInterface dialogInterface, int i) {
        DownloadController.Preset preset;
        DownloadController.Preset defaultPreset;
        String key;
        SharedPreferences.Editor editor = MessagesController.getMainSettings(this.currentAccount).edit();
        for (int a = 0; a < 3; a++) {
            if (a == 0) {
                preset = DownloadController.getInstance(this.currentAccount).mobilePreset;
                defaultPreset = DownloadController.getInstance(this.currentAccount).mediumPreset;
                key = "mobilePreset";
            } else if (a == 1) {
                preset = DownloadController.getInstance(this.currentAccount).wifiPreset;
                defaultPreset = DownloadController.getInstance(this.currentAccount).highPreset;
                key = "wifiPreset";
            } else {
                preset = DownloadController.getInstance(this.currentAccount).roamingPreset;
                defaultPreset = DownloadController.getInstance(this.currentAccount).lowPreset;
                key = "roamingPreset";
            }
            preset.set(defaultPreset);
            preset.enabled = defaultPreset.isEnabled();
            DownloadController.getInstance(this.currentAccount).currentMobilePreset = 3;
            editor.putInt("currentMobilePreset", 3);
            DownloadController.getInstance(this.currentAccount).currentWifiPreset = 3;
            editor.putInt("currentWifiPreset", 3);
            DownloadController.getInstance(this.currentAccount).currentRoamingPreset = 3;
            editor.putInt("currentRoamingPreset", 3);
            editor.putString(key, preset.toString());
        }
        editor.commit();
        DownloadController.getInstance(this.currentAccount).checkAutodownloadSettings();
        for (int a2 = 0; a2 < 3; a2++) {
            DownloadController.getInstance(this.currentAccount).savePresetToServer(a2);
        }
        this.listAdapter.notifyItemRangeChanged(this.mobileRow, 4);
    }

    public /* synthetic */ void lambda$null$1$DataSettingsActivity(SharedPreferences preferences, int position, DialogInterface dialog, int which) {
        int val = -1;
        if (which == 0) {
            val = 0;
        } else if (which == 1) {
            val = 3;
        } else if (which == 2) {
            val = 1;
        } else if (which == 3) {
            val = 2;
        }
        if (val != -1) {
            preferences.edit().putInt("VoipDataSaving", val).commit();
        }
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyItemChanged(position);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onDialogDismiss(Dialog dialog) {
        DownloadController.getInstance(this.currentAccount).checkAutodownloadSettings();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return DataSettingsActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String text;
            boolean enabled;
            DownloadController.Preset preset;
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                if (position == DataSettingsActivity.this.proxySection2Row) {
                    holder.itemView.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                    return;
                } else {
                    holder.itemView.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                    return;
                }
            }
            if (itemViewType == 1) {
                TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
                textCell.setCanDisable(false);
                textCell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                if (position != DataSettingsActivity.this.storageUsageRow) {
                    if (position != DataSettingsActivity.this.useLessDataForCallsRow) {
                        if (position != DataSettingsActivity.this.dataUsageRow) {
                            if (position != DataSettingsActivity.this.proxyRow) {
                                if (position != DataSettingsActivity.this.resetDownloadRow) {
                                    if (position == DataSettingsActivity.this.quickRepliesRow) {
                                        textCell.setText(LocaleController.getString("VoipQuickReplies", R.string.VoipQuickReplies), false);
                                        return;
                                    }
                                    return;
                                } else {
                                    textCell.setCanDisable(true);
                                    textCell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText));
                                    textCell.setText(LocaleController.getString("ResetAutomaticMediaDownload", R.string.ResetAutomaticMediaDownload), false);
                                    return;
                                }
                            }
                            textCell.setText(LocaleController.getString("ProxySettings", R.string.ProxySettings), false);
                            return;
                        }
                        textCell.setText(LocaleController.getString("NetworkUsage", R.string.NetworkUsage), false);
                        return;
                    }
                    SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                    String value = null;
                    int i = preferences.getInt("VoipDataSaving", VoIPHelper.getDataSavingDefault());
                    if (i == 0) {
                        value = LocaleController.getString("UseLessDataNever", R.string.UseLessDataNever);
                    } else if (i == 1) {
                        value = LocaleController.getString("UseLessDataOnMobile", R.string.UseLessDataOnMobile);
                    } else if (i == 2) {
                        value = LocaleController.getString("UseLessDataAlways", R.string.UseLessDataAlways);
                    } else if (i == 3) {
                        value = LocaleController.getString("UseLessDataOnRoaming", R.string.UseLessDataOnRoaming);
                    }
                    textCell.setTextAndValue(LocaleController.getString("VoipUseLessData", R.string.VoipUseLessData), value, true);
                    return;
                }
                textCell.setText(LocaleController.getString("StorageUsage", R.string.StorageUsage), true);
                return;
            }
            if (itemViewType == 2) {
                HeaderCell headerCell = (HeaderCell) holder.itemView;
                if (position != DataSettingsActivity.this.mediaDownloadSectionRow) {
                    if (position != DataSettingsActivity.this.usageSectionRow) {
                        if (position != DataSettingsActivity.this.callsSectionRow) {
                            if (position != DataSettingsActivity.this.proxySectionRow) {
                                if (position != DataSettingsActivity.this.streamSectionRow) {
                                    if (position == DataSettingsActivity.this.autoplayHeaderRow) {
                                        headerCell.setText(LocaleController.getString("AutoplayMedia", R.string.AutoplayMedia));
                                        return;
                                    }
                                    return;
                                }
                                headerCell.setText(LocaleController.getString("Streaming", R.string.Streaming));
                                return;
                            }
                            headerCell.setText(LocaleController.getString("Proxy", R.string.Proxy));
                            return;
                        }
                        headerCell.setText(LocaleController.getString("Calls", R.string.Calls));
                        return;
                    }
                    headerCell.setText(LocaleController.getString("DataUsage", R.string.DataUsage));
                    return;
                }
                headerCell.setText(LocaleController.getString("AutomaticMediaDownload", R.string.AutomaticMediaDownload));
                return;
            }
            if (itemViewType == 3) {
                TextCheckCell checkCell = (TextCheckCell) holder.itemView;
                if (position == DataSettingsActivity.this.enableStreamRow) {
                    checkCell.setTextAndCheck(LocaleController.getString("EnableStreaming", R.string.EnableStreaming), SharedConfig.streamMedia, DataSettingsActivity.this.enableAllStreamRow != -1);
                    return;
                }
                if (position != DataSettingsActivity.this.enableCacheStreamRow) {
                    if (position != DataSettingsActivity.this.enableMkvRow) {
                        if (position != DataSettingsActivity.this.enableAllStreamRow) {
                            if (position != DataSettingsActivity.this.autoplayGifsRow) {
                                if (position == DataSettingsActivity.this.autoplayVideoRow) {
                                    checkCell.setTextAndCheck(LocaleController.getString("AutoplayVideo", R.string.AutoplayVideo), SharedConfig.autoplayVideo, false);
                                    return;
                                }
                                return;
                            }
                            checkCell.setTextAndCheck(LocaleController.getString("AutoplayGIF", R.string.AutoplayGIF), SharedConfig.autoplayGifs, true);
                            return;
                        }
                        checkCell.setTextAndCheck("(beta only) Stream All Videos", SharedConfig.streamAllVideo, false);
                        return;
                    }
                    checkCell.setTextAndCheck("(beta only) Show MKV as Video", SharedConfig.streamMkv, true);
                    return;
                }
                return;
            }
            if (itemViewType == 4) {
                TextInfoPrivacyCell cell = (TextInfoPrivacyCell) holder.itemView;
                if (position == DataSettingsActivity.this.enableAllStreamInfoRow) {
                    cell.setText(LocaleController.getString("EnableAllStreamingInfo", R.string.EnableAllStreamingInfo));
                    return;
                }
                return;
            }
            if (itemViewType == 5) {
                NotificationsCheckCell checkCell2 = (NotificationsCheckCell) holder.itemView;
                StringBuilder builder = new StringBuilder();
                if (position != DataSettingsActivity.this.mobileRow) {
                    if (position == DataSettingsActivity.this.wifiRow) {
                        String text2 = LocaleController.getString("WhenConnectedOnWiFi", R.string.WhenConnectedOnWiFi);
                        boolean enabled2 = DownloadController.getInstance(DataSettingsActivity.this.currentAccount).wifiPreset.enabled;
                        text = text2;
                        enabled = enabled2;
                        preset = DownloadController.getInstance(DataSettingsActivity.this.currentAccount).getCurrentWiFiPreset();
                    } else {
                        String text3 = LocaleController.getString("WhenRoaming", R.string.WhenRoaming);
                        boolean enabled3 = DownloadController.getInstance(DataSettingsActivity.this.currentAccount).roamingPreset.enabled;
                        text = text3;
                        enabled = enabled3;
                        preset = DownloadController.getInstance(DataSettingsActivity.this.currentAccount).getCurrentRoamingPreset();
                    }
                } else {
                    String text4 = LocaleController.getString("WhenUsingMobileData", R.string.WhenUsingMobileData);
                    boolean enabled4 = DownloadController.getInstance(DataSettingsActivity.this.currentAccount).mobilePreset.enabled;
                    text = text4;
                    enabled = enabled4;
                    preset = DownloadController.getInstance(DataSettingsActivity.this.currentAccount).getCurrentMobilePreset();
                }
                boolean photos = false;
                boolean videos = false;
                boolean files = false;
                int count = 0;
                for (int a = 0; a < preset.mask.length; a++) {
                    if (!photos && (preset.mask[a] & 1) != 0) {
                        count++;
                        photos = true;
                    }
                    if (!videos && (preset.mask[a] & 4) != 0) {
                        count++;
                        videos = true;
                    }
                    if (!files && (preset.mask[a] & 8) != 0) {
                        count++;
                        files = true;
                    }
                }
                if (preset.enabled && count != 0) {
                    if (photos) {
                        builder.append(LocaleController.getString("AutoDownloadPhotosOn", R.string.AutoDownloadPhotosOn));
                    }
                    if (videos) {
                        if (builder.length() > 0) {
                            builder.append(", ");
                        }
                        builder.append(LocaleController.getString("AutoDownloadVideosOn", R.string.AutoDownloadVideosOn));
                        builder.append(String.format(" (%1$s)", AndroidUtilities.formatFileSize(preset.sizes[DownloadController.typeToIndex(4)], true)));
                    }
                    if (files) {
                        if (builder.length() > 0) {
                            builder.append(", ");
                        }
                        builder.append(LocaleController.getString("AutoDownloadFilesOn", R.string.AutoDownloadFilesOn));
                        builder.append(String.format(" (%1$s)", AndroidUtilities.formatFileSize(preset.sizes[DownloadController.typeToIndex(8)], true)));
                    }
                } else {
                    builder.append(LocaleController.getString("NoMediaAutoDownload", R.string.NoMediaAutoDownload));
                }
                checkCell2.setTextAndValueAndCheck(text, builder, (photos || videos || files) && enabled, 0, true, true);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            int viewType = holder.getItemViewType();
            if (viewType == 3) {
                TextCheckCell checkCell = (TextCheckCell) holder.itemView;
                int position = holder.getAdapterPosition();
                if (position != DataSettingsActivity.this.enableCacheStreamRow) {
                    if (position != DataSettingsActivity.this.enableStreamRow) {
                        if (position != DataSettingsActivity.this.enableAllStreamRow) {
                            if (position != DataSettingsActivity.this.enableMkvRow) {
                                if (position != DataSettingsActivity.this.autoplayGifsRow) {
                                    if (position == DataSettingsActivity.this.autoplayVideoRow) {
                                        checkCell.setChecked(SharedConfig.autoplayVideo);
                                        return;
                                    }
                                    return;
                                }
                                checkCell.setChecked(SharedConfig.autoplayGifs);
                                return;
                            }
                            checkCell.setChecked(SharedConfig.streamMkv);
                            return;
                        }
                        checkCell.setChecked(SharedConfig.streamAllVideo);
                        return;
                    }
                    checkCell.setChecked(SharedConfig.streamMedia);
                    return;
                }
                checkCell.setChecked(SharedConfig.saveStreamMedia);
            }
        }

        public boolean isRowEnabled(int position) {
            if (position != DataSettingsActivity.this.resetDownloadRow) {
                return position == DataSettingsActivity.this.mobileRow || position == DataSettingsActivity.this.roamingRow || position == DataSettingsActivity.this.wifiRow || position == DataSettingsActivity.this.storageUsageRow || position == DataSettingsActivity.this.useLessDataForCallsRow || position == DataSettingsActivity.this.dataUsageRow || position == DataSettingsActivity.this.proxyRow || position == DataSettingsActivity.this.enableCacheStreamRow || position == DataSettingsActivity.this.enableStreamRow || position == DataSettingsActivity.this.enableAllStreamRow || position == DataSettingsActivity.this.enableMkvRow || position == DataSettingsActivity.this.quickRepliesRow || position == DataSettingsActivity.this.autoplayVideoRow || position == DataSettingsActivity.this.autoplayGifsRow;
            }
            DownloadController controller = DownloadController.getInstance(DataSettingsActivity.this.currentAccount);
            return (controller.lowPreset.equals(controller.getCurrentRoamingPreset()) && controller.lowPreset.isEnabled() == controller.roamingPreset.enabled && controller.mediumPreset.equals(controller.getCurrentMobilePreset()) && controller.mediumPreset.isEnabled() == controller.mobilePreset.enabled && controller.highPreset.equals(controller.getCurrentWiFiPreset()) && controller.highPreset.isEnabled() == controller.wifiPreset.enabled) ? false : true;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return isRowEnabled(holder.getAdapterPosition());
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new ShadowSectionCell(this.mContext);
            } else if (viewType == 1) {
                view = new TextSettingsCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 2) {
                view = new HeaderCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 3) {
                view = new TextCheckCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 4) {
                view = new TextInfoPrivacyCell(this.mContext);
                view.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
            } else if (viewType == 5) {
                view = new NotificationsCheckCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != DataSettingsActivity.this.mediaDownloadSection2Row && position != DataSettingsActivity.this.usageSection2Row && position != DataSettingsActivity.this.callsSection2Row && position != DataSettingsActivity.this.proxySection2Row && position != DataSettingsActivity.this.autoplaySectionRow) {
                if (position != DataSettingsActivity.this.mediaDownloadSectionRow && position != DataSettingsActivity.this.streamSectionRow && position != DataSettingsActivity.this.callsSectionRow && position != DataSettingsActivity.this.usageSectionRow && position != DataSettingsActivity.this.proxySectionRow && position != DataSettingsActivity.this.autoplayHeaderRow) {
                    if (position != DataSettingsActivity.this.enableCacheStreamRow && position != DataSettingsActivity.this.enableStreamRow && position != DataSettingsActivity.this.enableAllStreamRow && position != DataSettingsActivity.this.enableMkvRow && position != DataSettingsActivity.this.autoplayGifsRow && position != DataSettingsActivity.this.autoplayVideoRow) {
                        if (position != DataSettingsActivity.this.enableAllStreamInfoRow) {
                            if (position == DataSettingsActivity.this.mobileRow || position == DataSettingsActivity.this.wifiRow || position == DataSettingsActivity.this.roamingRow) {
                                return 5;
                            }
                            return 1;
                        }
                        return 4;
                    }
                    return 3;
                }
                return 2;
            }
            return 0;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextSettingsCell.class, TextCheckCell.class, HeaderCell.class, NotificationsCheckCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4)};
    }
}
