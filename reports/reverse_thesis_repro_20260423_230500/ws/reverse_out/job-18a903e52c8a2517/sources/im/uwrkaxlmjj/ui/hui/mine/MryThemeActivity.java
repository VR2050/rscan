package im.uwrkaxlmjj.ui.hui.mine;

import android.animation.ObjectAnimator;
import android.app.Activity;
import android.app.TimePickerDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.location.Address;
import android.location.Geocoder;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Vibrator;
import android.text.TextPaint;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.TimePicker;
import androidx.core.content.FileProvider;
import androidx.core.view.MotionEventCompat;
import androidx.core.view.ViewCompat;
import androidx.exifinterface.media.ExifInterface;
import androidx.recyclerview.widget.DefaultItemAnimator;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import com.just.agentweb.DefaultWebClient;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.support.ArrayUtils;
import im.uwrkaxlmjj.messenger.time.SunDate;
import im.uwrkaxlmjj.ui.StickersActivity;
import im.uwrkaxlmjj.ui.ThemePreviewActivity;
import im.uwrkaxlmjj.ui.ThemeSetUrlActivity;
import im.uwrkaxlmjj.ui.WallpapersListActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.BrightnessControlCell;
import im.uwrkaxlmjj.ui.cells.ChatListCell;
import im.uwrkaxlmjj.ui.cells.ChatMessageCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.NotificationsCheckCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.cells.ThemePreviewMessagesCell;
import im.uwrkaxlmjj.ui.cells.ThemeTypeCell;
import im.uwrkaxlmjj.ui.cells.ThemesHorizontalListCell;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.SeekBarView;
import im.uwrkaxlmjj.ui.components.ShareAlert;
import im.uwrkaxlmjj.ui.components.ThemeEditorView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hcells.MryTextCheckCell;
import im.uwrkaxlmjj.ui.hui.decoration.TopBottomDecoration;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialogStyle;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MryThemeActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    public static final int THEME_TYPE_BASIC = 0;
    public static final int THEME_TYPE_NIGHT = 1;
    public static final int THEME_TYPE_OTHER = 2;
    private static final int create_theme = 1;
    private int automaticBrightnessInfoRow;
    private int automaticBrightnessRow;
    private int automaticHeaderRow;
    private int backgroundRow;
    private int chatListHeaderRow;
    private int chatListInfoRow;
    private int chatListRow;
    private int contactsReimportRow;
    private int contactsSortRow;
    private int currentType;
    private int customTabsRow;
    private ArrayList<Theme.ThemeInfo> darkThemes = new ArrayList<>();
    private ArrayList<Theme.ThemeInfo> defaultThemes = new ArrayList<>();
    private int directShareRow;
    private int distanceRow;
    private int emojiRow;
    private int enableAnimationsRow;
    private GpsLocationListener gpsLocationListener;
    boolean hasThemeAccents;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private GpsLocationListener networkLocationListener;
    private int newThemeInfoRow;
    private int nightAutomaticRow;
    private int nightDisabledRow;
    private int nightScheduledRow;
    private int nightThemeRow;
    private int nightTypeInfoRow;
    private int preferedHeaderRow;
    private boolean previousByLocation;
    private int previousUpdatedType;
    private int raiseToSpeakRow;
    private int rowCount;
    private int saveToGalleryRow;
    private int scheduleFromRow;
    private int scheduleFromToInfoRow;
    private int scheduleHeaderRow;
    private int scheduleLocationInfoRow;
    private int scheduleLocationRow;
    private int scheduleToRow;
    private int scheduleUpdateLocationRow;
    private int sendByEnterRow;
    private int settings2Row;
    private int settingsRow;
    private int stickersRow;
    private int stickersSection2Row;
    private int textSizeHeaderRow;
    private int textSizeRow;
    private int themeAccentListRow;
    private int themeHeaderRow;
    private int themeInfoRow;
    private int themeListRow;
    private ThemesHorizontalListCell themesHorizontalListCell;
    private boolean updatingLocation;

    public interface SizeChooseViewDelegate {
        void onSizeChanged();
    }

    private class GpsLocationListener implements LocationListener {
        private GpsLocationListener() {
        }

        /* synthetic */ GpsLocationListener(MryThemeActivity x0, AnonymousClass1 x1) {
            this();
        }

        @Override // android.location.LocationListener
        public void onLocationChanged(Location location) {
            if (location != null) {
                MryThemeActivity.this.stopLocationUpdate();
                MryThemeActivity.this.updateSunTime(location, false);
            }
        }

        @Override // android.location.LocationListener
        public void onStatusChanged(String provider, int status, Bundle extras) {
        }

        @Override // android.location.LocationListener
        public void onProviderEnabled(String provider) {
        }

        @Override // android.location.LocationListener
        public void onProviderDisabled(String provider) {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class TextSizeCell extends FrameLayout {
        private int endFontSize;
        private int lastWidth;
        private ThemePreviewMessagesCell messagesCell;
        private SeekBarView sizeBar;
        private int startFontSize;
        private TextPaint textPaint;

        public TextSizeCell(Context context) {
            super(context);
            this.startFontSize = 12;
            this.endFontSize = 30;
            setWillNotDraw(false);
            TextPaint textPaint = new TextPaint(1);
            this.textPaint = textPaint;
            textPaint.setTextSize(AndroidUtilities.dp(16.0f));
            SeekBarView seekBarView = new SeekBarView(context);
            this.sizeBar = seekBarView;
            seekBarView.setReportChanges(true);
            this.sizeBar.setDelegate(new SeekBarView.SeekBarViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$TextSizeCell$2xWXtAwfbM7Q9wzi57fpwjopz94
                @Override // im.uwrkaxlmjj.ui.components.SeekBarView.SeekBarViewDelegate
                public final void onSeekBarDrag(float f) {
                    this.f$0.lambda$new$0$MryThemeActivity$TextSizeCell(f);
                }
            });
            addView(this.sizeBar, LayoutHelper.createFrame(-1.0f, 38.0f, 51, 9.0f, 5.0f, 43.0f, 0.0f));
            ThemePreviewMessagesCell themePreviewMessagesCell = new ThemePreviewMessagesCell(context, MryThemeActivity.this.parentLayout, 0);
            this.messagesCell = themePreviewMessagesCell;
            addView(themePreviewMessagesCell, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 0.0f, 53.0f, 0.0f, 0.0f));
        }

        public /* synthetic */ void lambda$new$0$MryThemeActivity$TextSizeCell(float progress) {
            int fontSize = Math.round(this.startFontSize + ((this.endFontSize - r0) * progress));
            if (fontSize != SharedConfig.fontSize) {
                SharedConfig.fontSize = fontSize;
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                SharedPreferences.Editor editor = preferences.edit();
                editor.putInt("fons_size", SharedConfig.fontSize);
                editor.commit();
                Theme.chat_msgTextPaint.setTextSize(AndroidUtilities.dp(SharedConfig.fontSize));
                int firstVisPos = MryThemeActivity.this.layoutManager.findFirstVisibleItemPosition();
                View firstVisView = firstVisPos != -1 ? MryThemeActivity.this.layoutManager.findViewByPosition(firstVisPos) : null;
                int top = firstVisView != null ? firstVisView.getTop() : 0;
                ChatMessageCell[] cells = this.messagesCell.getCells();
                for (int a = 0; a < cells.length; a++) {
                    cells[a].getMessageObject().resetLayout();
                    cells[a].requestLayout();
                }
                if (firstVisView != null) {
                    MryThemeActivity.this.layoutManager.scrollToPositionWithOffset(firstVisPos, top);
                }
            }
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            this.textPaint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteValueText));
            canvas.drawText("" + SharedConfig.fontSize, getMeasuredWidth() - AndroidUtilities.dp(39.0f), AndroidUtilities.dp(28.0f), this.textPaint);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            int w = View.MeasureSpec.getSize(widthMeasureSpec);
            if (this.lastWidth != w) {
                SeekBarView seekBarView = this.sizeBar;
                int i = SharedConfig.fontSize;
                int i2 = this.startFontSize;
                seekBarView.setProgress((i - i2) / (this.endFontSize - i2));
                this.lastWidth = w;
            }
        }

        @Override // android.view.View
        public void invalidate() {
            super.invalidate();
            this.messagesCell.invalidate();
            this.sizeBar.invalidate();
        }
    }

    public MryThemeActivity(int type) {
        AnonymousClass1 anonymousClass1 = null;
        this.gpsLocationListener = new GpsLocationListener(this, anonymousClass1);
        this.networkLocationListener = new GpsLocationListener(this, anonymousClass1);
        this.currentType = type;
        updateRows(true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateRows(boolean notify) {
        int i;
        int i2;
        int oldRowCount = this.rowCount;
        int prevThemeAccentListRow = this.themeAccentListRow;
        this.rowCount = 0;
        this.emojiRow = -1;
        this.contactsReimportRow = -1;
        this.contactsSortRow = -1;
        this.scheduleLocationRow = -1;
        this.scheduleUpdateLocationRow = -1;
        this.scheduleLocationInfoRow = -1;
        this.nightDisabledRow = -1;
        this.nightScheduledRow = -1;
        this.nightAutomaticRow = -1;
        this.nightTypeInfoRow = -1;
        this.scheduleHeaderRow = -1;
        this.nightThemeRow = -1;
        this.newThemeInfoRow = -1;
        this.scheduleFromRow = -1;
        this.scheduleToRow = -1;
        this.scheduleFromToInfoRow = -1;
        this.themeListRow = -1;
        this.themeAccentListRow = -1;
        this.themeInfoRow = -1;
        this.preferedHeaderRow = -1;
        this.automaticHeaderRow = -1;
        this.automaticBrightnessRow = -1;
        this.automaticBrightnessInfoRow = -1;
        this.textSizeHeaderRow = -1;
        this.themeHeaderRow = -1;
        this.chatListHeaderRow = -1;
        this.chatListRow = -1;
        this.chatListInfoRow = -1;
        this.textSizeRow = -1;
        this.backgroundRow = -1;
        this.settingsRow = -1;
        this.customTabsRow = -1;
        this.directShareRow = -1;
        this.enableAnimationsRow = -1;
        this.raiseToSpeakRow = -1;
        this.sendByEnterRow = -1;
        this.saveToGalleryRow = -1;
        this.distanceRow = -1;
        this.settings2Row = -1;
        this.stickersRow = -1;
        this.stickersSection2Row = -1;
        if (this.currentType == 0) {
            this.defaultThemes.clear();
            this.darkThemes.clear();
            int N = Theme.themes.size();
            for (int a = 0; a < N; a++) {
                Theme.ThemeInfo themeInfo = Theme.themes.get(a);
                if (themeInfo.pathToFile != null) {
                    this.darkThemes.add(themeInfo);
                } else {
                    this.defaultThemes.add(themeInfo);
                }
            }
            Collections.sort(this.defaultThemes, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$X-X8P_LButRvH1tqk0gFMukMbWM
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return Integer.compare(((Theme.ThemeInfo) obj).sortIndex, ((Theme.ThemeInfo) obj2).sortIndex);
                }
            });
            int i3 = this.rowCount;
            int i4 = i3 + 1;
            this.rowCount = i4;
            this.textSizeHeaderRow = i3;
            int i5 = i4 + 1;
            this.rowCount = i5;
            this.textSizeRow = i4;
            int i6 = i5 + 1;
            this.rowCount = i6;
            this.backgroundRow = i5;
            int i7 = i6 + 1;
            this.rowCount = i7;
            this.newThemeInfoRow = i6;
            int i8 = i7 + 1;
            this.rowCount = i8;
            this.themeHeaderRow = i7;
            this.rowCount = i8 + 1;
            this.themeListRow = i8;
            boolean z = Theme.getCurrentTheme().accentColorOptions != null;
            this.hasThemeAccents = z;
            ThemesHorizontalListCell themesHorizontalListCell = this.themesHorizontalListCell;
            if (themesHorizontalListCell != null) {
                themesHorizontalListCell.setDrawDivider(z);
            }
            if (this.hasThemeAccents) {
                int i9 = this.rowCount;
                this.rowCount = i9 + 1;
                this.themeAccentListRow = i9;
            }
            int i10 = this.rowCount;
            int i11 = i10 + 1;
            this.rowCount = i11;
            this.themeInfoRow = i10;
            int i12 = i11 + 1;
            this.rowCount = i12;
            this.chatListHeaderRow = i11;
            int i13 = i12 + 1;
            this.rowCount = i13;
            this.chatListRow = i12;
            int i14 = i13 + 1;
            this.rowCount = i14;
            this.chatListInfoRow = i13;
            int i15 = i14 + 1;
            this.rowCount = i15;
            this.settingsRow = i14;
            int i16 = i15 + 1;
            this.rowCount = i16;
            this.nightThemeRow = i15;
            int i17 = i16 + 1;
            this.rowCount = i17;
            this.customTabsRow = i16;
            int i18 = i17 + 1;
            this.rowCount = i18;
            this.directShareRow = i17;
            int i19 = i18 + 1;
            this.rowCount = i19;
            this.enableAnimationsRow = i18;
            int i20 = i19 + 1;
            this.rowCount = i20;
            this.emojiRow = i19;
            int i21 = i20 + 1;
            this.rowCount = i21;
            this.raiseToSpeakRow = i20;
            int i22 = i21 + 1;
            this.rowCount = i22;
            this.sendByEnterRow = i21;
            int i23 = i22 + 1;
            this.rowCount = i23;
            this.saveToGalleryRow = i22;
            int i24 = i23 + 1;
            this.rowCount = i24;
            this.distanceRow = i23;
            int i25 = i24 + 1;
            this.rowCount = i25;
            this.settings2Row = i24;
            int i26 = i25 + 1;
            this.rowCount = i26;
            this.stickersRow = i25;
            this.rowCount = i26 + 1;
            this.stickersSection2Row = i26;
        } else {
            this.darkThemes.clear();
            int N2 = Theme.themes.size();
            for (int a2 = 0; a2 < N2; a2++) {
                Theme.ThemeInfo themeInfo2 = Theme.themes.get(a2);
                if (!themeInfo2.isLight() && (themeInfo2.info == null || themeInfo2.info.document != null)) {
                    this.darkThemes.add(themeInfo2);
                }
            }
            int a3 = this.rowCount;
            int i27 = a3 + 1;
            this.rowCount = i27;
            this.nightDisabledRow = a3;
            int i28 = i27 + 1;
            this.rowCount = i28;
            this.nightScheduledRow = i27;
            int i29 = i28 + 1;
            this.rowCount = i29;
            this.nightAutomaticRow = i28;
            this.rowCount = i29 + 1;
            this.nightTypeInfoRow = i29;
            if (Theme.selectedAutoNightType == 1) {
                int i30 = this.rowCount;
                int i31 = i30 + 1;
                this.rowCount = i31;
                this.scheduleHeaderRow = i30;
                this.rowCount = i31 + 1;
                this.scheduleLocationRow = i31;
                if (Theme.autoNightScheduleByLocation) {
                    int i32 = this.rowCount;
                    int i33 = i32 + 1;
                    this.rowCount = i33;
                    this.scheduleUpdateLocationRow = i32;
                    this.rowCount = i33 + 1;
                    this.scheduleLocationInfoRow = i33;
                } else {
                    int i34 = this.rowCount;
                    int i35 = i34 + 1;
                    this.rowCount = i35;
                    this.scheduleFromRow = i34;
                    int i36 = i35 + 1;
                    this.rowCount = i36;
                    this.scheduleToRow = i35;
                    this.rowCount = i36 + 1;
                    this.scheduleFromToInfoRow = i36;
                }
            } else if (Theme.selectedAutoNightType == 2) {
                int i37 = this.rowCount;
                int i38 = i37 + 1;
                this.rowCount = i38;
                this.automaticHeaderRow = i37;
                int i39 = i38 + 1;
                this.rowCount = i39;
                this.automaticBrightnessRow = i38;
                this.rowCount = i39 + 1;
                this.automaticBrightnessInfoRow = i39;
            }
            if (Theme.selectedAutoNightType != 0) {
                int i40 = this.rowCount;
                int i41 = i40 + 1;
                this.rowCount = i41;
                this.preferedHeaderRow = i40;
                this.rowCount = i41 + 1;
                this.themeListRow = i41;
                boolean z2 = Theme.getCurrentNightTheme().accentColorOptions != null;
                this.hasThemeAccents = z2;
                ThemesHorizontalListCell themesHorizontalListCell2 = this.themesHorizontalListCell;
                if (themesHorizontalListCell2 != null) {
                    themesHorizontalListCell2.setDrawDivider(z2);
                }
                if (this.hasThemeAccents) {
                    int i42 = this.rowCount;
                    this.rowCount = i42 + 1;
                    this.themeAccentListRow = i42;
                }
                int i43 = this.rowCount;
                this.rowCount = i43 + 1;
                this.themeInfoRow = i43;
            }
        }
        if (this.listAdapter != null) {
            if (this.currentType != 1 || this.previousUpdatedType == Theme.selectedAutoNightType || (i2 = this.previousUpdatedType) == -1) {
                if (notify || this.previousUpdatedType == -1) {
                    ThemesHorizontalListCell themesHorizontalListCell3 = this.themesHorizontalListCell;
                    if (themesHorizontalListCell3 != null) {
                        themesHorizontalListCell3.notifyDataSetChanged(this.listView.getWidth());
                    }
                    this.listAdapter.notifyDataSetChanged();
                } else if (prevThemeAccentListRow == -1 && (i = this.themeAccentListRow) != -1) {
                    this.listAdapter.notifyItemInserted(i);
                } else if (prevThemeAccentListRow != -1 && this.themeAccentListRow == -1) {
                    this.listAdapter.notifyItemRemoved(prevThemeAccentListRow);
                } else {
                    int i44 = this.themeAccentListRow;
                    if (i44 != -1) {
                        this.listAdapter.notifyItemChanged(i44);
                    }
                }
            } else {
                int start = this.nightTypeInfoRow + 1;
                if (i2 != Theme.selectedAutoNightType) {
                    int a4 = 0;
                    while (a4 < 3) {
                        RecyclerListView.Holder holder = (RecyclerListView.Holder) this.listView.findViewHolderForAdapterPosition(a4);
                        if (holder != null) {
                            ((ThemeTypeCell) holder.itemView).setTypeChecked(a4 == Theme.selectedAutoNightType);
                        }
                        a4++;
                    }
                    if (Theme.selectedAutoNightType == 0) {
                        this.listAdapter.notifyItemRangeRemoved(start, oldRowCount - start);
                    } else if (Theme.selectedAutoNightType == 1) {
                        int i45 = this.previousUpdatedType;
                        if (i45 == 0) {
                            this.listAdapter.notifyItemRangeInserted(start, this.rowCount - start);
                        } else if (i45 == 2) {
                            this.listAdapter.notifyItemRangeRemoved(start, 3);
                            this.listAdapter.notifyItemRangeInserted(start, Theme.autoNightScheduleByLocation ? 4 : 5);
                        }
                    } else if (Theme.selectedAutoNightType == 2) {
                        int i46 = this.previousUpdatedType;
                        if (i46 == 0) {
                            this.listAdapter.notifyItemRangeInserted(start, this.rowCount - start);
                        } else if (i46 == 1) {
                            this.listAdapter.notifyItemRangeRemoved(start, Theme.autoNightScheduleByLocation ? 4 : 5);
                            this.listAdapter.notifyItemRangeInserted(start, 3);
                        }
                    }
                } else if (this.previousByLocation != Theme.autoNightScheduleByLocation) {
                    this.listAdapter.notifyItemRangeRemoved(start + 2, Theme.autoNightScheduleByLocation ? 3 : 2);
                    this.listAdapter.notifyItemRangeInserted(start + 2, Theme.autoNightScheduleByLocation ? 2 : 3);
                }
            }
        }
        if (this.currentType == 1) {
            this.previousByLocation = Theme.autoNightScheduleByLocation;
            this.previousUpdatedType = Theme.selectedAutoNightType;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.locationPermissionGranted);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didSetNewWallpapper);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.themeListUpdated);
        if (this.currentType == 0) {
            Theme.loadRemoteThemes(this.currentAccount, true);
            Theme.checkCurrentRemoteTheme(true);
        }
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        stopLocationUpdate();
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.locationPermissionGranted);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didSetNewWallpapper);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.themeListUpdated);
        Theme.saveAutoNightThemeConfig();
        AndroidUtilities.removeAdjustResize(getParentActivity(), this.classGuid);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.locationPermissionGranted) {
            updateSunTime(null, true);
            return;
        }
        if (id == NotificationCenter.didSetNewWallpapper) {
            RecyclerListView recyclerListView = this.listView;
            if (recyclerListView != null) {
                recyclerListView.invalidateViews();
                return;
            }
            return;
        }
        if (id == NotificationCenter.themeListUpdated) {
            updateRows(true);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(false);
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        if (this.currentType == 0) {
            this.actionBar.setTitle(LocaleController.getString("ChatSettings", R.string.ChatSettings));
            ActionBarMenu menu = this.actionBar.createMenu();
            ActionBarMenuItem item = menu.addItem(0, R.drawable.ic_ab_other);
            item.setContentDescription(LocaleController.getString("AccDescrMoreOptions", R.string.AccDescrMoreOptions));
            item.addSubItem(1, R.drawable.menu_palette, LocaleController.getString("CreateNewThemeMenu", R.string.CreateNewThemeMenu));
        } else {
            this.actionBar.setTitle(LocaleController.getString("AutoNightTheme", R.string.AutoNightTheme));
        }
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass1());
        this.listAdapter = new ListAdapter(context);
        FrameLayout frameLayout = new FrameLayout(context);
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.fragmentView = frameLayout;
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView.setLayoutManager(linearLayoutManager);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setAdapter(this.listAdapter);
        ((DefaultItemAnimator) this.listView.getItemAnimator()).setDelayAnimations(false);
        this.listView.addItemDecoration(new TopBottomDecoration(10, 0));
        this.listView.setOverScrollMode(2);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListenerExtended() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$O7pQm8cArOhRPVqiAliDDHnfXCY
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListenerExtended
            public final void onItemClick(View view, int i, float f, float f2) {
                this.f$0.lambda$createView$3$MryThemeActivity(view, i, f, f2);
            }
        });
        return this.fragmentView;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.mine.MryThemeActivity$1, reason: invalid class name */
    class AnonymousClass1 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass1() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            if (id == -1) {
                MryThemeActivity.this.finishFragment();
                return;
            }
            if (id != 1 || MryThemeActivity.this.getParentActivity() == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(MryThemeActivity.this.getParentActivity());
            builder.setTitle(LocaleController.getString("NewTheme", R.string.NewTheme));
            builder.setMessage(LocaleController.getString("CreateNewThemeAlert", R.string.CreateNewThemeAlert));
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            builder.setPositiveButton(LocaleController.getString("CreateTheme", R.string.CreateTheme), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$1$2TrWzkEjyvgLNtdHRUcA5ohiEms
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$onItemClick$0$MryThemeActivity$1(dialogInterface, i);
                }
            });
            MryThemeActivity.this.showDialog(builder.create());
        }

        public /* synthetic */ void lambda$onItemClick$0$MryThemeActivity$1(DialogInterface dialog, int which) {
            MryThemeActivity.this.openThemeCreate();
        }
    }

    public /* synthetic */ void lambda$createView$3$MryThemeActivity(View view, final int position, float x, float y) {
        int currentHour;
        int currentMinute;
        int i;
        String str;
        if (position == this.enableAnimationsRow) {
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            boolean animations = preferences.getBoolean("view_animations", true);
            SharedPreferences.Editor editor = preferences.edit();
            editor.putBoolean("view_animations", !animations);
            editor.commit();
            if (view instanceof MryTextCheckCell) {
                ((MryTextCheckCell) view).setChecked(!animations);
                return;
            }
            return;
        }
        if (position == this.backgroundRow) {
            presentFragment(new WallpapersListActivity(0));
            return;
        }
        if (position == this.sendByEnterRow) {
            SharedPreferences preferences2 = MessagesController.getGlobalMainSettings();
            boolean send = preferences2.getBoolean("send_by_enter", false);
            SharedPreferences.Editor editor2 = preferences2.edit();
            editor2.putBoolean("send_by_enter", !send);
            editor2.commit();
            if (view instanceof MryTextCheckCell) {
                ((MryTextCheckCell) view).setChecked(!send);
                return;
            }
            return;
        }
        if (position == this.raiseToSpeakRow) {
            SharedConfig.toogleRaiseToSpeak();
            if (view instanceof MryTextCheckCell) {
                ((MryTextCheckCell) view).setChecked(SharedConfig.raiseToSpeak);
                return;
            }
            return;
        }
        if (position == this.saveToGalleryRow) {
            SharedConfig.toggleSaveToGallery();
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.saveGallerySetChanged, Boolean.valueOf(SharedConfig.saveToGallery));
            if (view instanceof MryTextCheckCell) {
                ((MryTextCheckCell) view).setChecked(SharedConfig.saveToGallery);
                return;
            }
            return;
        }
        if (position == this.distanceRow) {
            if (getParentActivity() == null) {
                return;
            }
            XDialog.Builder builder = new XDialog.Builder(getParentActivity());
            builder.setStyle(XDialogStyle.IOS);
            builder.setTitle(LocaleController.getString("DistanceUnitsTitle", R.string.DistanceUnitsTitle));
            builder.setItems(new CharSequence[]{LocaleController.getString("DistanceUnitsAutomatic", R.string.DistanceUnitsAutomatic), LocaleController.getString("DistanceUnitsKilometers", R.string.DistanceUnitsKilometers), LocaleController.getString("DistanceUnitsMiles", R.string.DistanceUnitsMiles)}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.MryThemeActivity.2
                @Override // android.content.DialogInterface.OnClickListener
                public void onClick(DialogInterface dialog, int which) {
                    SharedConfig.setDistanceSystemType(which);
                    RecyclerView.ViewHolder holder = MryThemeActivity.this.listView.findViewHolderForAdapterPosition(MryThemeActivity.this.distanceRow);
                    if (holder != null) {
                        MryThemeActivity.this.listAdapter.onBindViewHolder(holder, MryThemeActivity.this.distanceRow);
                    }
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder.create());
            return;
        }
        if (position == this.customTabsRow) {
            SharedConfig.toggleCustomTabs();
            if (view instanceof MryTextCheckCell) {
                ((MryTextCheckCell) view).setChecked(SharedConfig.customTabs);
                return;
            }
            return;
        }
        if (position == this.directShareRow) {
            SharedConfig.toggleDirectShare();
            if (view instanceof MryTextCheckCell) {
                ((MryTextCheckCell) view).setChecked(SharedConfig.directShare);
                return;
            }
            return;
        }
        if (position != this.contactsReimportRow) {
            if (position == this.contactsSortRow) {
                if (getParentActivity() == null) {
                    return;
                }
                AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
                builder2.setTitle(LocaleController.getString("SortBy", R.string.SortBy));
                builder2.setItems(new CharSequence[]{LocaleController.getString("Default", R.string.Default), LocaleController.getString("SortFirstName", R.string.SortFirstName), LocaleController.getString("SortLastName", R.string.SortLastName)}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$Hda9ONlX1y6pJ6nB5KjGhahjDJE
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i2) {
                        this.f$0.lambda$null$1$MryThemeActivity(position, dialogInterface, i2);
                    }
                });
                builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                showDialog(builder2.create());
                return;
            }
            if (position == this.stickersRow) {
                presentFragment(new StickersActivity(0));
                return;
            }
            if (position == this.emojiRow) {
                SharedConfig.toggleBigEmoji();
                if (view instanceof MryTextCheckCell) {
                    ((MryTextCheckCell) view).setChecked(SharedConfig.allowBigEmoji);
                    return;
                }
                return;
            }
            if (position == this.nightThemeRow) {
                if ((LocaleController.isRTL && x <= AndroidUtilities.dp(76.0f)) || (!LocaleController.isRTL && x >= view.getMeasuredWidth() - AndroidUtilities.dp(76.0f))) {
                    NotificationsCheckCell checkCell = (NotificationsCheckCell) view;
                    if (Theme.selectedAutoNightType == 0) {
                        Theme.selectedAutoNightType = 2;
                        checkCell.setChecked(true);
                    } else {
                        Theme.selectedAutoNightType = 0;
                        checkCell.setChecked(false);
                    }
                    Theme.saveAutoNightThemeConfig();
                    Theme.checkAutoNightThemeConditions();
                    boolean enabled = Theme.selectedAutoNightType != 0;
                    String value = enabled ? Theme.getCurrentNightThemeName() : LocaleController.getString("AutoNightThemeOff", R.string.AutoNightThemeOff);
                    if (enabled) {
                        if (Theme.selectedAutoNightType == 1) {
                            i = R.string.AutoNightScheduled;
                            str = "AutoNightScheduled";
                        } else {
                            i = R.string.AutoNightAdaptive;
                            str = "AutoNightAdaptive";
                        }
                        String type = LocaleController.getString(str, i);
                        value = type + " " + value;
                    }
                    checkCell.setTextAndValueAndCheck(LocaleController.getString("AutoNightTheme", R.string.AutoNightTheme), value, enabled, true);
                    return;
                }
                presentFragment(new MryThemeActivity(1));
                return;
            }
            if (position == this.nightDisabledRow) {
                Theme.selectedAutoNightType = 0;
                updateRows(true);
                Theme.checkAutoNightThemeConditions();
                return;
            }
            if (position == this.nightScheduledRow) {
                Theme.selectedAutoNightType = 1;
                if (Theme.autoNightScheduleByLocation) {
                    updateSunTime(null, true);
                }
                updateRows(true);
                Theme.checkAutoNightThemeConditions();
                return;
            }
            if (position == this.nightAutomaticRow) {
                Theme.selectedAutoNightType = 2;
                updateRows(true);
                Theme.checkAutoNightThemeConditions();
                return;
            }
            if (position == this.scheduleLocationRow) {
                Theme.autoNightScheduleByLocation = !Theme.autoNightScheduleByLocation;
                ((MryTextCheckCell) view).setChecked(Theme.autoNightScheduleByLocation);
                updateRows(true);
                if (Theme.autoNightScheduleByLocation) {
                    updateSunTime(null, true);
                }
                Theme.checkAutoNightThemeConditions();
                return;
            }
            if (position == this.scheduleFromRow || position == this.scheduleToRow) {
                if (getParentActivity() == null) {
                    return;
                }
                if (position == this.scheduleFromRow) {
                    currentHour = Theme.autoNightDayStartTime / 60;
                    currentMinute = Theme.autoNightDayStartTime - (currentHour * 60);
                } else {
                    currentHour = Theme.autoNightDayEndTime / 60;
                    currentMinute = Theme.autoNightDayEndTime - (currentHour * 60);
                }
                final TextSettingsCell cell = (TextSettingsCell) view;
                TimePickerDialog dialog = new TimePickerDialog(getParentActivity(), new TimePickerDialog.OnTimeSetListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$M15VLafGLtnUqIDMYp_Qyb1RCPc
                    @Override // android.app.TimePickerDialog.OnTimeSetListener
                    public final void onTimeSet(TimePicker timePicker, int i2, int i3) {
                        this.f$0.lambda$null$2$MryThemeActivity(position, cell, timePicker, i2, i3);
                    }
                }, currentHour, currentMinute, true);
                showDialog(dialog);
                return;
            }
            if (position == this.scheduleUpdateLocationRow) {
                updateSunTime(null, true);
            }
        }
    }

    public /* synthetic */ void lambda$null$1$MryThemeActivity(int position, DialogInterface dialog, int which) {
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        SharedPreferences.Editor editor = preferences.edit();
        editor.putInt("sortContactsBy", which);
        editor.commit();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyItemChanged(position);
        }
    }

    public /* synthetic */ void lambda$null$2$MryThemeActivity(int position, TextSettingsCell cell, TimePicker view1, int hourOfDay, int minute) {
        int time = (hourOfDay * 60) + minute;
        if (position == this.scheduleFromRow) {
            Theme.autoNightDayStartTime = time;
            cell.setTextAndValue(LocaleController.getString("AutoNightFrom", R.string.AutoNightFrom), String.format("%02d:%02d", Integer.valueOf(hourOfDay), Integer.valueOf(minute)), true);
        } else {
            Theme.autoNightDayEndTime = time;
            cell.setTextAndValue(LocaleController.getString("AutoNightTo", R.string.AutoNightTo), String.format("%02d:%02d", Integer.valueOf(hourOfDay), Integer.valueOf(minute)), true);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        if (this.listAdapter != null) {
            updateRows(true);
        }
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openThemeCreate() {
        final EditTextBoldCursor editText = new EditTextBoldCursor(getParentActivity());
        editText.setBackgroundDrawable(Theme.createEditTextDrawable(getParentActivity(), true));
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("NewTheme", R.string.NewTheme));
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.setPositiveButton(LocaleController.getString("Create", R.string.Create), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$FfdLEeKVp6f2BJKtDMEuFS8nqeA
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                MryThemeActivity.lambda$openThemeCreate$4(dialogInterface, i);
            }
        });
        LinearLayout linearLayout = new LinearLayout(getParentActivity());
        linearLayout.setOrientation(1);
        builder.setView(linearLayout);
        TextView message = new TextView(getParentActivity());
        message.setText(LocaleController.formatString("EnterThemeName", R.string.EnterThemeName, new Object[0]));
        message.setTextSize(16.0f);
        message.setPadding(AndroidUtilities.dp(23.0f), AndroidUtilities.dp(12.0f), AndroidUtilities.dp(23.0f), AndroidUtilities.dp(6.0f));
        message.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        linearLayout.addView(message, LayoutHelper.createLinear(-1, -2));
        editText.setTextSize(1, 16.0f);
        editText.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        editText.setMaxLines(1);
        editText.setLines(1);
        editText.setInputType(16385);
        editText.setGravity(51);
        editText.setSingleLine(true);
        editText.setImeOptions(6);
        editText.setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        editText.setCursorSize(AndroidUtilities.dp(20.0f));
        editText.setCursorWidth(1.5f);
        editText.setPadding(0, AndroidUtilities.dp(4.0f), 0, 0);
        linearLayout.addView(editText, LayoutHelper.createLinear(-1, 36, 51, 24, 6, 24, 0));
        editText.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$5Ew77by36aHt8xtJpY_HGxpH9I0
            @Override // android.widget.TextView.OnEditorActionListener
            public final boolean onEditorAction(TextView textView, int i, KeyEvent keyEvent) {
                return MryThemeActivity.lambda$openThemeCreate$5(textView, i, keyEvent);
            }
        });
        editText.setText(generateThemeName());
        editText.setSelection(editText.length());
        final AlertDialog alertDialog = builder.create();
        alertDialog.setOnShowListener(new DialogInterface.OnShowListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$Fi7sWvcD9DbzmVIuw6PAiibPRfQ
            @Override // android.content.DialogInterface.OnShowListener
            public final void onShow(DialogInterface dialogInterface) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$VRleIivw7vez_2UHK8x-KLiCaUc
                    @Override // java.lang.Runnable
                    public final void run() {
                        MryThemeActivity.lambda$null$6(editTextBoldCursor);
                    }
                });
            }
        });
        showDialog(alertDialog);
        alertDialog.getButton(-1).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$dCQ0fzUnBGLDdh0DUUFkIclu3Kc
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$openThemeCreate$8$MryThemeActivity(editText, alertDialog, view);
            }
        });
    }

    static /* synthetic */ void lambda$openThemeCreate$4(DialogInterface dialog, int which) {
    }

    static /* synthetic */ boolean lambda$openThemeCreate$5(TextView textView, int i, KeyEvent keyEvent) {
        AndroidUtilities.hideKeyboard(textView);
        return false;
    }

    static /* synthetic */ void lambda$null$6(EditTextBoldCursor editText) {
        editText.requestFocus();
        AndroidUtilities.showKeyboard(editText);
    }

    public /* synthetic */ void lambda$openThemeCreate$8$MryThemeActivity(EditTextBoldCursor editText, AlertDialog alertDialog, View v) {
        if (editText.length() == 0) {
            Vibrator vibrator = (Vibrator) ApplicationLoader.applicationContext.getSystemService("vibrator");
            if (vibrator != null) {
                vibrator.vibrate(200L);
            }
            AndroidUtilities.shakeView(editText, 2.0f, 0);
            return;
        }
        ThemeEditorView themeEditorView = new ThemeEditorView();
        themeEditorView.show(getParentActivity(), Theme.createNewTheme(editText.getText().toString()));
        updateRows(true);
        alertDialog.dismiss();
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        if (!preferences.getBoolean("themehint", false)) {
            preferences.edit().putBoolean("themehint", true).commit();
            try {
                ToastUtils.show(R.string.CreateNewThemeHelp);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateSunTime(Location lastKnownLocation, boolean forceUpdate) {
        Activity activity;
        LocationManager locationManager = (LocationManager) ApplicationLoader.applicationContext.getSystemService("location");
        if (Build.VERSION.SDK_INT >= 23 && (activity = getParentActivity()) != null && activity.checkSelfPermission(PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION) != 0) {
            activity.requestPermissions(new String[]{PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION, "android.permission.ACCESS_FINE_LOCATION"}, 2);
            return;
        }
        if (getParentActivity() != null) {
            if (!getParentActivity().getPackageManager().hasSystemFeature("android.hardware.location.gps")) {
                return;
            }
            try {
                LocationManager lm = (LocationManager) ApplicationLoader.applicationContext.getSystemService("location");
                if (!lm.isProviderEnabled("gps")) {
                    AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                    builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                    builder.setMessage(LocaleController.getString("GpsDisabledAlert", R.string.GpsDisabledAlert));
                    builder.setPositiveButton(LocaleController.getString("ConnectingToProxyEnable", R.string.ConnectingToProxyEnable), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$wi6YsEvjSrILTsiohrShDvDXAYk
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            this.f$0.lambda$updateSunTime$9$MryThemeActivity(dialogInterface, i);
                        }
                    });
                    builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                    showDialog(builder.create());
                    return;
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        try {
            lastKnownLocation = locationManager.getLastKnownLocation("gps");
            if (lastKnownLocation == null) {
                lastKnownLocation = locationManager.getLastKnownLocation("network");
            }
            if (lastKnownLocation == null) {
                lastKnownLocation = locationManager.getLastKnownLocation("passive");
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        if (lastKnownLocation == null || forceUpdate) {
            startLocationUpdate();
            if (lastKnownLocation == null) {
                return;
            }
        }
        Theme.autoNightLocationLatitude = lastKnownLocation.getLatitude();
        Theme.autoNightLocationLongitude = lastKnownLocation.getLongitude();
        int[] time = SunDate.calculateSunriseSunset(Theme.autoNightLocationLatitude, Theme.autoNightLocationLongitude);
        Theme.autoNightSunriseTime = time[0];
        Theme.autoNightSunsetTime = time[1];
        Theme.autoNightCityName = null;
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(System.currentTimeMillis());
        Theme.autoNightLastSunCheckDay = calendar.get(5);
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$FyUvsAh6f5sXs8nMqXRZTnCQA0s
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateSunTime$11$MryThemeActivity();
            }
        });
        RecyclerListView.Holder holder = (RecyclerListView.Holder) this.listView.findViewHolderForAdapterPosition(this.scheduleLocationInfoRow);
        if (holder != null && (holder.itemView instanceof TextInfoPrivacyCell)) {
            ((TextInfoPrivacyCell) holder.itemView).setText(getLocationSunString());
        }
        if (Theme.autoNightScheduleByLocation && Theme.selectedAutoNightType == 1) {
            Theme.checkAutoNightThemeConditions();
        }
    }

    public /* synthetic */ void lambda$updateSunTime$9$MryThemeActivity(DialogInterface dialog, int id) {
        if (getParentActivity() == null) {
            return;
        }
        try {
            getParentActivity().startActivity(new Intent("android.settings.LOCATION_SOURCE_SETTINGS"));
        } catch (Exception e) {
        }
    }

    public /* synthetic */ void lambda$updateSunTime$11$MryThemeActivity() {
        String name;
        try {
            Geocoder gcd = new Geocoder(ApplicationLoader.applicationContext, Locale.getDefault());
            List<Address> addresses = gcd.getFromLocation(Theme.autoNightLocationLatitude, Theme.autoNightLocationLongitude, 1);
            if (addresses.size() > 0) {
                name = addresses.get(0).getLocality();
            } else {
                name = null;
            }
        } catch (Exception e) {
            name = null;
        }
        final String nameFinal = name;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$ymM6fqZfaDWdzeWheoALalL5Rfk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$10$MryThemeActivity(nameFinal);
            }
        });
    }

    public /* synthetic */ void lambda$null$10$MryThemeActivity(String nameFinal) {
        RecyclerListView.Holder holder;
        Theme.autoNightCityName = nameFinal;
        if (Theme.autoNightCityName == null) {
            Theme.autoNightCityName = String.format("(%.06f, %.06f)", Double.valueOf(Theme.autoNightLocationLatitude), Double.valueOf(Theme.autoNightLocationLongitude));
        }
        Theme.saveAutoNightThemeConfig();
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null && (holder = (RecyclerListView.Holder) recyclerListView.findViewHolderForAdapterPosition(this.scheduleUpdateLocationRow)) != null && (holder.itemView instanceof TextSettingsCell)) {
            ((TextSettingsCell) holder.itemView).setTextAndValue(LocaleController.getString("AutoNightUpdateLocation", R.string.AutoNightUpdateLocation), Theme.autoNightCityName, false);
        }
    }

    private void startLocationUpdate() {
        if (this.updatingLocation) {
            return;
        }
        this.updatingLocation = true;
        LocationManager locationManager = (LocationManager) ApplicationLoader.applicationContext.getSystemService("location");
        try {
            locationManager.requestLocationUpdates("gps", 1L, 0.0f, this.gpsLocationListener);
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            locationManager.requestLocationUpdates("network", 1L, 0.0f, this.networkLocationListener);
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void stopLocationUpdate() {
        this.updatingLocation = false;
        LocationManager locationManager = (LocationManager) ApplicationLoader.applicationContext.getSystemService("location");
        locationManager.removeUpdates(this.gpsLocationListener);
        locationManager.removeUpdates(this.networkLocationListener);
    }

    private void showPermissionAlert(boolean byButton) {
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        if (byButton) {
            builder.setMessage(LocaleController.getString("PermissionNoLocationPosition", R.string.PermissionNoLocationPosition));
        } else {
            builder.setMessage(LocaleController.getString("PermissionNoLocation", R.string.PermissionNoLocation));
        }
        builder.setNegativeButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$QVFhg5aIDLmUZdQxo3_WiAF7kEY
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showPermissionAlert$12$MryThemeActivity(dialogInterface, i);
            }
        });
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$showPermissionAlert$12$MryThemeActivity(DialogInterface dialog, int which) {
        if (getParentActivity() == null) {
            return;
        }
        try {
            Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
            intent.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
            getParentActivity().startActivity(intent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String getLocationSunString() {
        int currentHour = Theme.autoNightSunriseTime / 60;
        int currentMinute = Theme.autoNightSunriseTime - (currentHour * 60);
        String sunriseTimeStr = String.format("%02d:%02d", Integer.valueOf(currentHour), Integer.valueOf(currentMinute));
        int currentHour2 = Theme.autoNightSunsetTime / 60;
        int currentMinute2 = Theme.autoNightSunsetTime - (currentHour2 * 60);
        String sunsetTimeStr = String.format("%02d:%02d", Integer.valueOf(currentHour2), Integer.valueOf(currentMinute2));
        return LocaleController.formatString("AutoNightUpdateLocationInfo", R.string.AutoNightUpdateLocationInfo, sunsetTimeStr, sunriseTimeStr);
    }

    private static class InnerAccentView extends View {
        private ObjectAnimator checkAnimator;
        private float checkedState;
        private int currentColor;
        private Theme.ThemeInfo currentTheme;
        private final Paint paint;

        InnerAccentView(Context context) {
            super(context);
            this.paint = new Paint(1);
        }

        void setThemeAndColor(Theme.ThemeInfo themeInfo, int color) {
            this.currentTheme = themeInfo;
            this.currentColor = color;
            updateCheckedState(false);
        }

        void updateCheckedState(boolean animate) {
            boolean checked = this.currentTheme.accentColor == this.currentColor;
            ObjectAnimator objectAnimator = this.checkAnimator;
            if (objectAnimator != null) {
                objectAnimator.cancel();
            }
            if (animate) {
                float[] fArr = new float[1];
                fArr[0] = checked ? 1.0f : 0.0f;
                ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, "checkedState", fArr);
                this.checkAnimator = objectAnimatorOfFloat;
                objectAnimatorOfFloat.setDuration(200L);
                this.checkAnimator.start();
                return;
            }
            setCheckedState(checked ? 1.0f : 0.0f);
        }

        public void setCheckedState(float state) {
            this.checkedState = state;
            invalidate();
        }

        public float getCheckedState() {
            return this.checkedState;
        }

        @Override // android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            updateCheckedState(false);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(62.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(62.0f), 1073741824));
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            float radius = AndroidUtilities.dp(20.0f);
            this.paint.setColor(this.currentColor);
            this.paint.setStyle(Paint.Style.STROKE);
            this.paint.setStrokeWidth(AndroidUtilities.dp(3.0f));
            this.paint.setAlpha(Math.round(this.checkedState * 255.0f));
            canvas.drawCircle(getMeasuredWidth() * 0.5f, getMeasuredHeight() * 0.5f, radius - (this.paint.getStrokeWidth() * 0.5f), this.paint);
            this.paint.setAlpha(255);
            this.paint.setStyle(Paint.Style.FILL);
            canvas.drawCircle(getMeasuredWidth() * 0.5f, getMeasuredHeight() * 0.5f, radius - (AndroidUtilities.dp(5.0f) * this.checkedState), this.paint);
        }
    }

    private static class InnerCustomAccentView extends View {
        private int[] colors;
        private final Paint paint;

        InnerCustomAccentView(Context context) {
            super(context);
            this.paint = new Paint(1);
            this.colors = new int[7];
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setTheme(Theme.ThemeInfo themeInfo) {
            int[] options = themeInfo == null ? null : themeInfo.accentColorOptions;
            if (options != null && options.length >= 8) {
                this.colors = new int[]{options[6], options[4], options[7], options[2], options[0], options[5], options[3]};
            } else {
                this.colors = new int[7];
            }
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(62.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(62.0f), 1073741824));
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            float centerX = getMeasuredWidth() * 0.5f;
            float centerY = getMeasuredHeight() * 0.5f;
            float radSmall = AndroidUtilities.dp(5.0f);
            float radRing = AndroidUtilities.dp(20.0f) - radSmall;
            this.paint.setStyle(Paint.Style.FILL);
            this.paint.setColor(this.colors[0]);
            canvas.drawCircle(centerX, centerY, radSmall, this.paint);
            double angle = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
            for (int a = 0; a < 6; a++) {
                float cx = (((float) Math.sin(angle)) * radRing) + centerX;
                float cy = centerY - (((float) Math.cos(angle)) * radRing);
                this.paint.setColor(this.colors[a + 1]);
                canvas.drawCircle(cx, cy, radSmall, this.paint);
                angle += 1.0471975511965976d;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ThemeAccentsListAdapter extends RecyclerListView.SelectionAdapter {
        private Theme.ThemeInfo currentTheme;
        private int extraColor;
        private boolean hasExtraColor;
        private Context mContext;
        private int[] options;

        ThemeAccentsListAdapter(Context context) {
            this.mContext = context;
            setHasStableIds(true);
            notifyDataSetChanged();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            Theme.ThemeInfo currentNightTheme = MryThemeActivity.this.currentType == 1 ? Theme.getCurrentNightTheme() : Theme.getCurrentTheme();
            this.currentTheme = currentNightTheme;
            int[] iArr = currentNightTheme.accentColorOptions;
            this.options = iArr;
            if (iArr != null && ArrayUtils.indexOf(iArr, this.currentTheme.accentColor) == -1) {
                this.extraColor = this.currentTheme.accentColor;
                this.hasExtraColor = true;
            }
            super.notifyDataSetChanged();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public long getItemId(int position) {
            return getAccentColor(position);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return position == getItemCount() - 1 ? 1 : 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            if (viewType == 0) {
                return new RecyclerListView.Holder(new InnerAccentView(this.mContext));
            }
            return new RecyclerListView.Holder(new InnerCustomAccentView(this.mContext));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = getItemViewType(position);
            if (itemViewType == 0) {
                InnerAccentView view = (InnerAccentView) holder.itemView;
                view.setThemeAndColor(this.currentTheme, getAccentColor(position));
            } else if (itemViewType == 1) {
                InnerCustomAccentView view2 = (InnerCustomAccentView) holder.itemView;
                view2.setTheme(this.currentTheme);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int[] iArr = this.options;
            if (iArr == null) {
                return 0;
            }
            return iArr.length + (this.hasExtraColor ? 1 : 0) + 1;
        }

        int getAccentColor(int pos) {
            int[] iArr = this.options;
            if (iArr == null) {
                return 0;
            }
            if (this.hasExtraColor && pos == iArr.length) {
                return this.extraColor;
            }
            int[] iArr2 = this.options;
            if (pos < iArr2.length) {
                return iArr2[pos];
            }
            return 0;
        }

        int findCurrentAccent() {
            if (this.hasExtraColor && this.extraColor == this.currentTheme.accentColor) {
                return this.options.length;
            }
            return ArrayUtils.indexOf(this.options, this.currentTheme.accentColor);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private boolean first = true;
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return MryThemeActivity.this.rowCount;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            return type == 0 || type == 1 || type == 4 || type == 7 || type == 10 || type == 11 || type == 12;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void showOptionsForTheme(final Theme.ThemeInfo themeInfo) {
            boolean hasDelete;
            String string;
            CharSequence[] items;
            int[] icons;
            if (MryThemeActivity.this.getParentActivity() != null) {
                if ((themeInfo.info != null && !themeInfo.themeLoaded) || MryThemeActivity.this.currentType == 1) {
                    return;
                }
                AlertDialog.Builder builder = new AlertDialog.Builder(MryThemeActivity.this.getParentActivity());
                if (themeInfo.pathToFile == null) {
                    hasDelete = false;
                    items = new CharSequence[]{null, LocaleController.getString("ExportTheme", R.string.ExportTheme)};
                    icons = new int[]{0, R.drawable.msg_shareout};
                } else {
                    hasDelete = themeInfo.info == null || !themeInfo.info.isDefault;
                    CharSequence[] charSequenceArr = new CharSequence[5];
                    charSequenceArr[0] = themeInfo.info != null ? LocaleController.getString("ShareFile", R.string.ShareFile) : null;
                    charSequenceArr[1] = LocaleController.getString("ExportTheme", R.string.ExportTheme);
                    if (themeInfo.info == null || (!themeInfo.info.isDefault && themeInfo.info.creator)) {
                        string = LocaleController.getString("Edit", R.string.Edit);
                    } else {
                        string = null;
                    }
                    charSequenceArr[2] = string;
                    charSequenceArr[3] = (themeInfo.info == null || !themeInfo.info.creator) ? null : LocaleController.getString("ThemeSetUrl", R.string.ThemeSetUrl);
                    charSequenceArr[4] = hasDelete ? LocaleController.getString("Delete", R.string.Delete) : null;
                    items = charSequenceArr;
                    icons = new int[]{R.drawable.msg_share, R.drawable.msg_shareout, R.drawable.msg_edit, R.drawable.msg_link, R.drawable.msg_delete};
                }
                builder.setItems(items, icons, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$ListAdapter$SEqYTqq-M8G6w1L3eB1bse1ZaGM
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$showOptionsForTheme$1$MryThemeActivity$ListAdapter(themeInfo, dialogInterface, i);
                    }
                });
                AlertDialog alertDialog = builder.create();
                MryThemeActivity.this.showDialog(alertDialog);
                if (hasDelete) {
                    alertDialog.setItemColor(alertDialog.getItemsCount() - 1, Theme.getColor(Theme.key_dialogTextRed2), Theme.getColor(Theme.key_dialogRedIcon));
                }
            }
        }

        /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:29:0x00be -> B:73:0x00e4). Please report as a decompilation issue!!! */
        public /* synthetic */ void lambda$showOptionsForTheme$1$MryThemeActivity$ListAdapter(final Theme.ThemeInfo themeInfo, DialogInterface dialog, int which) {
            File currentFile;
            if (MryThemeActivity.this.getParentActivity() == null) {
                return;
            }
            if (which == 0) {
                String link = DefaultWebClient.HTTPS_SCHEME + MessagesController.getInstance(MryThemeActivity.this.currentAccount).linkPrefix + "/addtheme/" + themeInfo.info.slug;
                MryThemeActivity.this.showDialog(new ShareAlert(MryThemeActivity.this.getParentActivity(), null, link, false, link, false));
                return;
            }
            if (which != 1) {
                if (which == 2) {
                    if (MryThemeActivity.this.parentLayout != null) {
                        Theme.applyTheme(themeInfo);
                        MryThemeActivity.this.parentLayout.rebuildAllFragmentViews(true, true);
                        new ThemeEditorView().show(MryThemeActivity.this.getParentActivity(), themeInfo);
                        return;
                    }
                    return;
                }
                if (which == 3) {
                    MryThemeActivity.this.presentFragment(new ThemeSetUrlActivity(themeInfo, false));
                    return;
                }
                if (MryThemeActivity.this.getParentActivity() == null) {
                    return;
                }
                AlertDialog.Builder builder1 = new AlertDialog.Builder(MryThemeActivity.this.getParentActivity());
                builder1.setMessage(LocaleController.getString("DeleteThemeAlert", R.string.DeleteThemeAlert));
                builder1.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder1.setPositiveButton(LocaleController.getString("Delete", R.string.Delete), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$ListAdapter$o9mxL4PjXETaoTE99VSazom2Q90
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$0$MryThemeActivity$ListAdapter(themeInfo, dialogInterface, i);
                    }
                });
                builder1.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                MryThemeActivity.this.showDialog(builder1.create());
                return;
            }
            if (themeInfo.pathToFile == null && themeInfo.assetName == null) {
                StringBuilder result = new StringBuilder();
                for (Map.Entry<String, Integer> entry : Theme.getDefaultColors().entrySet()) {
                    result.append(entry.getKey());
                    result.append("=");
                    result.append(entry.getValue());
                    result.append(ShellAdbUtils.COMMAND_LINE_END);
                }
                currentFile = new File(ApplicationLoader.getFilesDirFixed(), "default_theme.attheme");
                FileOutputStream stream = null;
                try {
                    try {
                        try {
                            stream = new FileOutputStream(currentFile);
                            stream.write(AndroidUtilities.getStringBytes(result.toString()));
                            stream.close();
                        } catch (Throwable th) {
                            if (stream != null) {
                                try {
                                    stream.close();
                                } catch (Exception e) {
                                    FileLog.e(e);
                                }
                            }
                            throw th;
                        }
                    } catch (Exception e2) {
                        FileLog.e(e2);
                        if (stream != null) {
                            stream.close();
                        }
                    }
                } catch (Exception e3) {
                    FileLog.e(e3);
                }
            } else if (themeInfo.assetName != null) {
                currentFile = Theme.getAssetFile(themeInfo.assetName);
            } else {
                currentFile = new File(themeInfo.pathToFile);
            }
            File finalFile = new File(FileLoader.getDirectory(4), FileLoader.fixFileName(currentFile.getName()));
            try {
                if (!AndroidUtilities.copyFile(currentFile, finalFile)) {
                    return;
                }
                Intent intent = new Intent("android.intent.action.SEND");
                intent.setType("text/xml");
                if (Build.VERSION.SDK_INT >= 24) {
                    try {
                        intent.putExtra("android.intent.extra.STREAM", FileProvider.getUriForFile(MryThemeActivity.this.getParentActivity(), "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", finalFile));
                        intent.setFlags(1);
                    } catch (Exception e4) {
                        intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(finalFile));
                    }
                } else {
                    intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(finalFile));
                }
                MryThemeActivity.this.startActivityForResult(Intent.createChooser(intent, LocaleController.getString("ShareFile", R.string.ShareFile)), SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
            } catch (Exception e5) {
                FileLog.e(e5);
            }
        }

        public /* synthetic */ void lambda$null$0$MryThemeActivity$ListAdapter(Theme.ThemeInfo themeInfo, DialogInterface dialogInterface, int i) {
            MryThemeActivity.this.getMessagesController().saveTheme(themeInfo, themeInfo == Theme.getCurrentNightTheme(), true);
            if (Theme.deleteTheme(themeInfo)) {
                MryThemeActivity.this.parentLayout.rebuildAllFragmentViews(true, true);
            }
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.themeListUpdated, new Object[0]);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View textSettingsCell;
            switch (viewType) {
                case 1:
                    textSettingsCell = new TextSettingsCell(this.mContext);
                    textSettingsCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 2:
                    textSettingsCell = new TextInfoPrivacyCell(this.mContext);
                    break;
                case 3:
                    View view = new ShadowSectionCell(this.mContext);
                    view.setBackgroundColor(0);
                    textSettingsCell = view;
                    break;
                case 4:
                    textSettingsCell = new ThemeTypeCell(this.mContext);
                    textSettingsCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 5:
                    textSettingsCell = new HeaderCell(this.mContext);
                    textSettingsCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 6:
                    textSettingsCell = new BrightnessControlCell(this.mContext) { // from class: im.uwrkaxlmjj.ui.hui.mine.MryThemeActivity.ListAdapter.1
                        @Override // im.uwrkaxlmjj.ui.cells.BrightnessControlCell
                        protected void didChangedValue(float value) {
                            int oldValue = (int) (Theme.autoNightBrighnessThreshold * 100.0f);
                            int newValue = (int) (value * 100.0f);
                            Theme.autoNightBrighnessThreshold = value;
                            if (oldValue != newValue) {
                                RecyclerListView.Holder holder = (RecyclerListView.Holder) MryThemeActivity.this.listView.findViewHolderForAdapterPosition(MryThemeActivity.this.automaticBrightnessInfoRow);
                                if (holder != null) {
                                    TextInfoPrivacyCell cell = (TextInfoPrivacyCell) holder.itemView;
                                    cell.setText(LocaleController.formatString("AutoNightBrightnessInfo", R.string.AutoNightBrightnessInfo, Integer.valueOf((int) (Theme.autoNightBrighnessThreshold * 100.0f))));
                                }
                                Theme.checkAutoNightThemeConditions(true);
                            }
                        }
                    };
                    textSettingsCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 7:
                    textSettingsCell = new MryTextCheckCell(this.mContext);
                    textSettingsCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 8:
                    textSettingsCell = MryThemeActivity.this.new TextSizeCell(this.mContext);
                    textSettingsCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 9:
                    textSettingsCell = new ChatListCell(this.mContext) { // from class: im.uwrkaxlmjj.ui.hui.mine.MryThemeActivity.ListAdapter.2
                        @Override // im.uwrkaxlmjj.ui.cells.ChatListCell
                        protected void didSelectChatType(boolean threeLines) {
                            SharedConfig.setUseThreeLinesLayout(threeLines);
                        }
                    };
                    textSettingsCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 10:
                    textSettingsCell = new NotificationsCheckCell(this.mContext, 21, 64);
                    textSettingsCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    break;
                case 11:
                    this.first = true;
                    MryThemeActivity.this.themesHorizontalListCell = new ThemesHorizontalListCell(this.mContext, MryThemeActivity.this.currentType, MryThemeActivity.this.defaultThemes, MryThemeActivity.this.darkThemes) { // from class: im.uwrkaxlmjj.ui.hui.mine.MryThemeActivity.ListAdapter.3
                        @Override // im.uwrkaxlmjj.ui.cells.ThemesHorizontalListCell
                        protected void showOptionsForTheme(Theme.ThemeInfo themeInfo) {
                            MryThemeActivity.this.listAdapter.showOptionsForTheme(themeInfo);
                        }

                        @Override // im.uwrkaxlmjj.ui.cells.ThemesHorizontalListCell
                        protected void presentFragment(BaseFragment fragment) {
                            MryThemeActivity.this.presentFragment(fragment);
                        }

                        @Override // im.uwrkaxlmjj.ui.cells.ThemesHorizontalListCell
                        protected void updateRows() {
                            MryThemeActivity.this.updateRows(false);
                        }
                    };
                    MryThemeActivity.this.themesHorizontalListCell.setDrawDivider(MryThemeActivity.this.hasThemeAccents);
                    textSettingsCell = MryThemeActivity.this.themesHorizontalListCell;
                    textSettingsCell.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(148.0f)));
                    break;
                default:
                    final RecyclerListView accentsListView = new TintRecyclerListView(this.mContext) { // from class: im.uwrkaxlmjj.ui.hui.mine.MryThemeActivity.ListAdapter.4
                        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
                        public boolean onInterceptTouchEvent(MotionEvent e) {
                            if (getParent() != null && getParent().getParent() != null) {
                                getParent().getParent().requestDisallowInterceptTouchEvent(true);
                            }
                            return super.onInterceptTouchEvent(e);
                        }
                    };
                    accentsListView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    accentsListView.setItemAnimator(null);
                    accentsListView.setLayoutAnimation(null);
                    accentsListView.setPadding(AndroidUtilities.dp(11.0f), 0, AndroidUtilities.dp(11.0f), 0);
                    accentsListView.setClipToPadding(false);
                    LinearLayoutManager accentsLayoutManager = new LinearLayoutManager(this.mContext);
                    accentsLayoutManager.setOrientation(0);
                    accentsListView.setLayoutManager(accentsLayoutManager);
                    final ThemeAccentsListAdapter accentsAdapter = MryThemeActivity.this.new ThemeAccentsListAdapter(this.mContext);
                    accentsListView.setAdapter(accentsAdapter);
                    accentsListView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryThemeActivity$ListAdapter$fP4_PKxM3aiIkxl5jNBO-7-us2k
                        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                        public final void onItemClick(View view2, int i) {
                            this.f$0.lambda$onCreateViewHolder$2$MryThemeActivity$ListAdapter(accentsAdapter, accentsListView, view2, i);
                        }
                    });
                    accentsListView.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(62.0f)));
                    textSettingsCell = accentsListView;
                    break;
            }
            return new RecyclerListView.Holder(textSettingsCell);
        }

        public /* synthetic */ void lambda$onCreateViewHolder$2$MryThemeActivity$ListAdapter(ThemeAccentsListAdapter accentsAdapter, RecyclerListView accentsListView, View view1, int position) {
            Theme.ThemeInfo currentTheme = MryThemeActivity.this.currentType == 1 ? Theme.getCurrentNightTheme() : Theme.getCurrentTheme();
            if (position == accentsAdapter.getItemCount() - 1) {
                MryThemeActivity mryThemeActivity = MryThemeActivity.this;
                mryThemeActivity.presentFragment(new ThemePreviewActivity(currentTheme, false, 1, mryThemeActivity.currentType == 1));
            } else {
                int newAccent = accentsAdapter.getAccentColor(position);
                if (currentTheme.accentColor != newAccent) {
                    Theme.saveThemeAccent(currentTheme, newAccent);
                    NotificationCenter globalInstance = NotificationCenter.getGlobalInstance();
                    int i = NotificationCenter.needSetDayNightTheme;
                    Object[] objArr = new Object[2];
                    objArr[0] = currentTheme;
                    objArr[1] = Boolean.valueOf(MryThemeActivity.this.currentType == 1);
                    globalInstance.postNotificationName(i, objArr);
                }
            }
            int left = view1.getLeft();
            int right = view1.getRight();
            int extra = AndroidUtilities.dp(52.0f);
            if (left - extra < 0) {
                accentsListView.smoothScrollBy(left - extra, 0);
            } else if (right + extra > accentsListView.getMeasuredWidth()) {
                accentsListView.smoothScrollBy((right + extra) - accentsListView.getMeasuredWidth(), 0);
            }
            int count = accentsListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = accentsListView.getChildAt(a);
                if (child instanceof InnerAccentView) {
                    ((InnerAccentView) child).updateCheckedState(true);
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String value;
            String value2;
            switch (holder.getItemViewType()) {
                case 1:
                    TextSettingsCell cell = (TextSettingsCell) holder.itemView;
                    if (position != MryThemeActivity.this.nightThemeRow) {
                        if (position != MryThemeActivity.this.scheduleFromRow) {
                            if (position != MryThemeActivity.this.scheduleToRow) {
                                if (position != MryThemeActivity.this.scheduleUpdateLocationRow) {
                                    if (position != MryThemeActivity.this.contactsSortRow) {
                                        if (position != MryThemeActivity.this.backgroundRow) {
                                            if (position != MryThemeActivity.this.contactsReimportRow) {
                                                if (position != MryThemeActivity.this.stickersRow) {
                                                    if (position == MryThemeActivity.this.distanceRow) {
                                                        if (SharedConfig.distanceSystemType == 0) {
                                                            value = LocaleController.getString("DistanceUnitsAutomatic", R.string.DistanceUnitsAutomatic);
                                                        } else if (SharedConfig.distanceSystemType == 1) {
                                                            value = LocaleController.getString("DistanceUnitsKilometers", R.string.DistanceUnitsKilometers);
                                                        } else {
                                                            value = LocaleController.getString("DistanceUnitsMiles", R.string.DistanceUnitsMiles);
                                                        }
                                                        cell.setTextAndValue(LocaleController.getString("DistanceUnits", R.string.DistanceUnits), value, false);
                                                    }
                                                } else {
                                                    cell.setText(LocaleController.getString("StickersAndMasks", R.string.StickersAndMasks), false);
                                                    cell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                                                }
                                            } else {
                                                cell.setText(LocaleController.getString("ImportContacts", R.string.ImportContacts), true);
                                            }
                                        } else {
                                            cell.setText(LocaleController.getString("ChangeChatBackground", R.string.ChangeChatBackground), false);
                                            cell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                                        }
                                    } else {
                                        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                                        int sort = preferences.getInt("sortContactsBy", 0);
                                        if (sort == 0) {
                                            value2 = LocaleController.getString("Default", R.string.Default);
                                        } else if (sort == 1) {
                                            value2 = LocaleController.getString("FirstName", R.string.SortFirstName);
                                        } else {
                                            value2 = LocaleController.getString("LastName", R.string.SortLastName);
                                        }
                                        cell.setTextAndValue(LocaleController.getString("SortBy", R.string.SortBy), value2, true);
                                    }
                                } else {
                                    cell.setTextAndValue(LocaleController.getString("AutoNightUpdateLocation", R.string.AutoNightUpdateLocation), Theme.autoNightCityName, false);
                                }
                            } else {
                                int currentHour = Theme.autoNightDayEndTime / 60;
                                int currentMinute = Theme.autoNightDayEndTime - (currentHour * 60);
                                cell.setTextAndValue(LocaleController.getString("AutoNightTo", R.string.AutoNightTo), String.format("%02d:%02d", Integer.valueOf(currentHour), Integer.valueOf(currentMinute)), false);
                            }
                        } else {
                            int currentHour2 = Theme.autoNightDayStartTime / 60;
                            int currentMinute2 = Theme.autoNightDayStartTime - (currentHour2 * 60);
                            cell.setTextAndValue(LocaleController.getString("AutoNightFrom", R.string.AutoNightFrom), String.format("%02d:%02d", Integer.valueOf(currentHour2), Integer.valueOf(currentMinute2)), true);
                        }
                    } else if (Theme.selectedAutoNightType == 0 || Theme.getCurrentNightTheme() == null) {
                        cell.setTextAndValue(LocaleController.getString("AutoNightTheme", R.string.AutoNightTheme), LocaleController.getString("AutoNightThemeOff", R.string.AutoNightThemeOff), false);
                    } else {
                        cell.setTextAndValue(LocaleController.getString("AutoNightTheme", R.string.AutoNightTheme), Theme.getCurrentNightThemeName(), false);
                    }
                    break;
                case 2:
                    TextInfoPrivacyCell cell2 = (TextInfoPrivacyCell) holder.itemView;
                    if (position != MryThemeActivity.this.automaticBrightnessInfoRow) {
                        if (position == MryThemeActivity.this.scheduleLocationInfoRow) {
                            cell2.setText(MryThemeActivity.this.getLocationSunString());
                        }
                    } else {
                        cell2.setText(LocaleController.formatString("AutoNightBrightnessInfo", R.string.AutoNightBrightnessInfo, Integer.valueOf((int) (Theme.autoNightBrighnessThreshold * 100.0f))));
                    }
                    break;
                case 4:
                    ThemeTypeCell typeCell = (ThemeTypeCell) holder.itemView;
                    if (position != MryThemeActivity.this.nightDisabledRow) {
                        if (position != MryThemeActivity.this.nightScheduledRow) {
                            if (position == MryThemeActivity.this.nightAutomaticRow) {
                                typeCell.setValue(LocaleController.getString("AutoNightAdaptive", R.string.AutoNightAdaptive), Theme.selectedAutoNightType == 2, false);
                            }
                        } else {
                            typeCell.setValue(LocaleController.getString("AutoNightScheduled", R.string.AutoNightScheduled), Theme.selectedAutoNightType == 1, true);
                        }
                    } else {
                        typeCell.setValue(LocaleController.getString("AutoNightDisabled", R.string.AutoNightDisabled), Theme.selectedAutoNightType == 0, true);
                    }
                    break;
                case 5:
                    HeaderCell headerCell = (HeaderCell) holder.itemView;
                    if (position != MryThemeActivity.this.scheduleHeaderRow) {
                        if (position != MryThemeActivity.this.automaticHeaderRow) {
                            if (position != MryThemeActivity.this.preferedHeaderRow) {
                                if (position != MryThemeActivity.this.settingsRow) {
                                    if (position != MryThemeActivity.this.themeHeaderRow) {
                                        if (position != MryThemeActivity.this.textSizeHeaderRow) {
                                            if (position == MryThemeActivity.this.chatListHeaderRow) {
                                                headerCell.setText(LocaleController.getString("ChatList", R.string.ChatList));
                                            }
                                        } else {
                                            headerCell.setText(LocaleController.getString("TextSizeHeader", R.string.TextSizeHeader));
                                            headerCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                                        }
                                    } else {
                                        headerCell.setText(LocaleController.getString("ColorTheme", R.string.ColorTheme));
                                    }
                                } else {
                                    headerCell.setText(LocaleController.getString("SETTINGS", R.string.SETTINGS));
                                }
                            } else {
                                headerCell.setText(LocaleController.getString("AutoNightPreferred", R.string.AutoNightPreferred));
                            }
                        } else {
                            headerCell.setText(LocaleController.getString("AutoNightBrightness", R.string.AutoNightBrightness));
                        }
                    } else {
                        headerCell.setText(LocaleController.getString("AutoNightSchedule", R.string.AutoNightSchedule));
                    }
                    break;
                case 6:
                    ((BrightnessControlCell) holder.itemView).setProgress(Theme.autoNightBrighnessThreshold);
                    break;
                case 7:
                    MryTextCheckCell textCheckCell = (MryTextCheckCell) holder.itemView;
                    if (position != MryThemeActivity.this.scheduleLocationRow) {
                        if (position != MryThemeActivity.this.enableAnimationsRow) {
                            if (position != MryThemeActivity.this.sendByEnterRow) {
                                if (position != MryThemeActivity.this.saveToGalleryRow) {
                                    if (position != MryThemeActivity.this.raiseToSpeakRow) {
                                        if (position != MryThemeActivity.this.customTabsRow) {
                                            if (position != MryThemeActivity.this.directShareRow) {
                                                if (position == MryThemeActivity.this.emojiRow) {
                                                    textCheckCell.setTextAndCheck(LocaleController.getString("LargeEmoji", R.string.LargeEmoji), SharedConfig.allowBigEmoji, true);
                                                }
                                            } else {
                                                textCheckCell.setTextAndValueAndCheck(LocaleController.getString("DirectShare", R.string.DirectShare), LocaleController.getString("DirectShareInfo", R.string.DirectShareInfo), SharedConfig.directShare, false, true);
                                            }
                                        } else {
                                            textCheckCell.setTextAndValueAndCheck(LocaleController.getString("ChromeCustomTabs", R.string.ChromeCustomTabs), LocaleController.getString("ChromeCustomTabsInfo", R.string.ChromeCustomTabsInfo), SharedConfig.customTabs, false, true);
                                        }
                                    } else {
                                        textCheckCell.setTextAndCheck(LocaleController.getString("RaiseToSpeak", R.string.RaiseToSpeak), SharedConfig.raiseToSpeak, true);
                                    }
                                } else {
                                    textCheckCell.setTextAndCheck(LocaleController.getString("SaveToGallerySettings", R.string.SaveToGallerySettings), SharedConfig.saveToGallery, true);
                                }
                            } else {
                                SharedPreferences preferences2 = MessagesController.getGlobalMainSettings();
                                textCheckCell.setTextAndCheck(LocaleController.getString("SendByEnter", R.string.SendByEnter), preferences2.getBoolean("send_by_enter", false), true);
                            }
                        } else {
                            SharedPreferences preferences3 = MessagesController.getGlobalMainSettings();
                            textCheckCell.setTextAndCheck(LocaleController.getString("EnableAnimations", R.string.EnableAnimations), preferences3.getBoolean("view_animations", true), true);
                        }
                    } else {
                        textCheckCell.setTextAndCheck(LocaleController.getString("AutoNightLocation", R.string.AutoNightLocation), Theme.autoNightScheduleByLocation, true);
                    }
                    break;
                case 10:
                    NotificationsCheckCell checkCell = (NotificationsCheckCell) holder.itemView;
                    if (position == MryThemeActivity.this.nightThemeRow) {
                        boolean enabled = Theme.selectedAutoNightType != 0;
                        String value3 = enabled ? Theme.getCurrentNightThemeName() : LocaleController.getString("AutoNightThemeOff", R.string.AutoNightThemeOff);
                        if (enabled) {
                            String type = Theme.selectedAutoNightType == 1 ? LocaleController.getString("AutoNightScheduled", R.string.AutoNightScheduled) : LocaleController.getString("AutoNightAdaptive", R.string.AutoNightAdaptive);
                            value3 = type + " " + value3;
                        }
                        String type2 = LocaleController.getString("AutoNightTheme", R.string.AutoNightTheme);
                        checkCell.setTextAndValueAndCheck(type2, value3, enabled, true);
                    }
                    break;
                case 11:
                    if (this.first) {
                        MryThemeActivity.this.themesHorizontalListCell.scrollToCurrentTheme(MryThemeActivity.this.listView.getMeasuredWidth(), false);
                        this.first = false;
                    }
                    break;
                case 12:
                    RecyclerListView accentsList = (RecyclerListView) holder.itemView;
                    ThemeAccentsListAdapter adapter = (ThemeAccentsListAdapter) accentsList.getAdapter();
                    adapter.notifyDataSetChanged();
                    int pos = adapter.findCurrentAccent();
                    if (pos == -1) {
                        pos = adapter.getItemCount() - 1;
                    }
                    if (pos != -1) {
                        ((LinearLayoutManager) accentsList.getLayoutManager()).scrollToPositionWithOffset(pos, (MryThemeActivity.this.listView.getMeasuredWidth() / 2) - AndroidUtilities.dp(42.0f));
                    }
                    break;
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            if (type == 4) {
                ((ThemeTypeCell) holder.itemView).setTypeChecked(holder.getAdapterPosition() == Theme.selectedAutoNightType);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == MryThemeActivity.this.scheduleFromRow || position == MryThemeActivity.this.distanceRow || position == MryThemeActivity.this.scheduleToRow || position == MryThemeActivity.this.scheduleUpdateLocationRow || position == MryThemeActivity.this.backgroundRow || position == MryThemeActivity.this.contactsReimportRow || position == MryThemeActivity.this.contactsSortRow || position == MryThemeActivity.this.stickersRow) {
                return 1;
            }
            if (position != MryThemeActivity.this.automaticBrightnessInfoRow && position != MryThemeActivity.this.scheduleLocationInfoRow) {
                if (position != MryThemeActivity.this.themeInfoRow && position != MryThemeActivity.this.nightTypeInfoRow && position != MryThemeActivity.this.scheduleFromToInfoRow && position != MryThemeActivity.this.stickersSection2Row && position != MryThemeActivity.this.settings2Row && position != MryThemeActivity.this.newThemeInfoRow && position != MryThemeActivity.this.chatListInfoRow) {
                    if (position != MryThemeActivity.this.nightDisabledRow && position != MryThemeActivity.this.nightScheduledRow && position != MryThemeActivity.this.nightAutomaticRow) {
                        if (position != MryThemeActivity.this.scheduleHeaderRow && position != MryThemeActivity.this.automaticHeaderRow && position != MryThemeActivity.this.preferedHeaderRow && position != MryThemeActivity.this.settingsRow && position != MryThemeActivity.this.themeHeaderRow && position != MryThemeActivity.this.textSizeHeaderRow && position != MryThemeActivity.this.chatListHeaderRow) {
                            if (position != MryThemeActivity.this.automaticBrightnessRow) {
                                if (position != MryThemeActivity.this.scheduleLocationRow && position != MryThemeActivity.this.enableAnimationsRow && position != MryThemeActivity.this.sendByEnterRow && position != MryThemeActivity.this.saveToGalleryRow && position != MryThemeActivity.this.raiseToSpeakRow && position != MryThemeActivity.this.customTabsRow && position != MryThemeActivity.this.directShareRow && position != MryThemeActivity.this.emojiRow) {
                                    if (position != MryThemeActivity.this.textSizeRow) {
                                        if (position != MryThemeActivity.this.chatListRow) {
                                            if (position != MryThemeActivity.this.nightThemeRow) {
                                                if (position == MryThemeActivity.this.themeListRow) {
                                                    return 11;
                                                }
                                                return position == MryThemeActivity.this.themeAccentListRow ? 12 : 1;
                                            }
                                            return 10;
                                        }
                                        return 9;
                                    }
                                    return 8;
                                }
                                return 7;
                            }
                            return 6;
                        }
                        return 5;
                    }
                    return 4;
                }
                return 3;
            }
            return 2;
        }
    }

    private static abstract class TintRecyclerListView extends RecyclerListView {
        TintRecyclerListView(Context context) {
            super(context);
        }
    }

    private String generateThemeName() {
        int color;
        List<String> adjectives = Arrays.asList("Ancient", "Antique", "Autumn", "Baby", "Barely", "Baroque", "Blazing", "Blushing", "Bohemian", "Bubbly", "Burning", "Buttered", "Classic", "Clear", "Cool", "Cosmic", "Cotton", "Cozy", "Crystal", "Dark", "Daring", "Darling", "Dawn", "Dazzling", "Deep", "Deepest", "Delicate", "Delightful", "Divine", "Double", "Downtown", "Dreamy", "Dusky", "Dusty", "Electric", "Enchanted", "Endless", "Evening", "Fantastic", "Flirty", "Forever", "Frigid", "Frosty", "Frozen", "Gentle", "Heavenly", "Hyper", "Icy", "Infinite", "Innocent", "Instant", "Luscious", "Lunar", "Lustrous", "Magic", "Majestic", "Mambo", "Midnight", "Millenium", "Morning", "Mystic", "Natural", "Neon", "Night", "Opaque", "Paradise", "Perfect", "Perky", "Polished", "Powerful", "Rich", "Royal", "Sheer", "Simply", "Sizzling", "Solar", "Sparkling", "Splendid", "Spicy", "Spring", "Stellar", "Sugared", "Summer", "Sunny", "Super", "Sweet", "Tender", "Tenacious", "Tidal", "Toasted", "Totally", "Tranquil", "Tropical", "True", "Twilight", "Twinkling", "Ultimate", "Ultra", "Velvety", "Vibrant", "Vintage", "Virtual", "Warm", "Warmest", "Whipped", "Wild", "Winsome");
        List<String> subjectives = Arrays.asList("Ambrosia", "Attack", "Avalanche", "Blast", "Bliss", "Blossom", "Blush", "Burst", "Butter", "Candy", "Carnival", "Charm", "Chiffon", "Cloud", "Comet", "Delight", "Dream", "Dust", "Fantasy", "Flame", ExifInterface.TAG_FLASH, "Fire", "Freeze", "Frost", "Glade", "Glaze", "Gleam", "Glimmer", "Glitter", "Glow", "Grande", "Haze", "Highlight", "Ice", "Illusion", "Intrigue", "Jewel", "Jubilee", "Kiss", "Lights", "Lollypop", "Love", "Luster", "Madness", "Matte", "Mirage", "Mist", "Moon", "Muse", "Myth", "Nectar", "Nova", "Parfait", "Passion", "Pop", "Rain", "Reflection", "Rhapsody", "Romance", "Satin", "Sensation", "Silk", "Shine", "Shadow", "Shimmer", "Sky", "Spice", "Star", "Sugar", "Sunrise", "Sunset", "Sun", "Twist", "Unbound", "Velvet", "Vibrant", "Waters", "Wine", "Wink", "Wonder", "Zone");
        HashMap<Integer, String> colors = new HashMap<>();
        colors.put(9306112, "Berry");
        colors.put(14598550, "Brandy");
        colors.put(8391495, "Cherry");
        colors.put(16744272, "Coral");
        colors.put(14372985, "Cranberry");
        colors.put(14423100, "Crimson");
        colors.put(14725375, "Mauve");
        colors.put(16761035, "Pink");
        colors.put(16711680, "Red");
        colors.put(16711807, "Rose");
        colors.put(8406555, "Russet");
        colors.put(16720896, "Scarlet");
        colors.put(15856113, "Seashell");
        colors.put(16724889, "Strawberry");
        colors.put(16760576, "Amber");
        colors.put(15438707, "Apricot");
        colors.put(16508850, "Banana");
        colors.put(10601738, "Citrus");
        colors.put(11560192, "Ginger");
        colors.put(16766720, "Gold");
        colors.put(16640272, "Lemon");
        colors.put(16753920, "Orange");
        colors.put(16770484, "Peach");
        colors.put(16739155, "Persimmon");
        colors.put(14996514, "Sunflower");
        colors.put(15893760, "Tangerine");
        colors.put(16763004, "Topaz");
        colors.put(16776960, "Yellow");
        colors.put(3688720, "Clover");
        colors.put(8628829, "Cucumber");
        colors.put(5294200, "Emerald");
        colors.put(11907932, "Olive");
        colors.put(Integer.valueOf(MotionEventCompat.ACTION_POINTER_INDEX_MASK), "Green");
        colors.put(43115, "Jade");
        colors.put(2730887, "Jungle");
        colors.put(12582656, "Lime");
        colors.put(776785, "Malachite");
        colors.put(10026904, "Mint");
        colors.put(11394989, "Moss");
        colors.put(3234721, "Azure");
        colors.put(255, "Blue");
        colors.put(18347, "Cobalt");
        colors.put(5204422, "Indigo");
        colors.put(96647, "Lagoon");
        colors.put(7461346, "Aquamarine");
        colors.put(1182351, "Ultramarine");
        colors.put(128, "Navy");
        colors.put(3101086, "Sapphire");
        colors.put(7788522, "Sky");
        colors.put(32896, "Teal");
        colors.put(4251856, "Turquoise");
        colors.put(10053324, "Amethyst");
        colors.put(5046581, "Blackberry");
        colors.put(6373457, "Eggplant");
        colors.put(13148872, "Lilac");
        colors.put(11894492, "Lavender");
        colors.put(13421823, "Periwinkle");
        colors.put(8663417, "Plum");
        colors.put(6684825, "Purple");
        colors.put(14204888, "Thistle");
        colors.put(14315734, "Orchid");
        colors.put(2361920, "Violet");
        colors.put(4137225, "Bronze");
        colors.put(3604994, "Chocolate");
        colors.put(8077056, "Cinnamon");
        colors.put(3153694, "Cocoa");
        colors.put(7365973, "Coffee");
        colors.put(7956873, "Rum");
        colors.put(5113350, "Mahogany");
        colors.put(7875865, "Mocha");
        colors.put(12759680, "Sand");
        colors.put(8924439, "Sienna");
        colors.put(7864585, "Maple");
        colors.put(15787660, "Khaki");
        colors.put(12088115, "Copper");
        colors.put(12144200, "Chestnut");
        colors.put(15653316, "Almond");
        colors.put(16776656, "Cream");
        colors.put(12186367, "Diamond");
        colors.put(11109127, "Honey");
        colors.put(16777200, "Ivory");
        colors.put(15392968, "Pearl");
        colors.put(15725299, "Porcelain");
        colors.put(13745832, "Vanilla");
        colors.put(Integer.valueOf(ViewCompat.MEASURED_SIZE_MASK), "White");
        colors.put(8421504, "Gray");
        colors.put(0, "Black");
        colors.put(15266260, "Chrome");
        colors.put(3556687, "Charcoal");
        colors.put(789277, "Ebony");
        colors.put(12632256, "Silver");
        colors.put(16119285, "Smoke");
        colors.put(2499381, "Steel");
        colors.put(5220413, "Apple");
        colors.put(8434628, "Glacier");
        colors.put(16693933, "Melon");
        colors.put(12929932, "Mulberry");
        colors.put(11126466, "Opal");
        colors.put(5547512, "Blue");
        Theme.ThemeInfo themeInfo = Theme.getCurrentTheme();
        if (themeInfo.accentColor == 0) {
            color = AndroidUtilities.calcDrawableColor(Theme.getCachedWallpaper())[0];
        } else {
            color = themeInfo.accentColor;
        }
        String minKey = null;
        int minValue = Integer.MAX_VALUE;
        int r1 = Color.red(color);
        int g1 = Color.green(color);
        int b1 = Color.blue(color);
        for (Map.Entry<Integer, String> entry : colors.entrySet()) {
            Integer value = entry.getKey();
            int r2 = Color.red(value.intValue());
            int g2 = Color.green(value.intValue());
            int b2 = Color.blue(value.intValue());
            HashMap<Integer, String> colors2 = colors;
            int rMean = (r1 + r2) / 2;
            int r = r1 - r2;
            int g = g1 - g2;
            int b = b1 - b2;
            int color2 = color;
            int color3 = rMean + 512;
            Theme.ThemeInfo themeInfo2 = themeInfo;
            int d = (((color3 * r) * r) >> 8) + (g * 4 * g) + ((((767 - rMean) * b) * b) >> 8);
            if (d < minValue) {
                String minKey2 = entry.getValue();
                minValue = d;
                minKey = minKey2;
            }
            colors = colors2;
            color = color2;
            themeInfo = themeInfo2;
        }
        if (Utilities.random.nextInt() % 2 == 0) {
            String result = adjectives.get(Utilities.random.nextInt(adjectives.size())) + " " + minKey;
            return result;
        }
        String result2 = minKey + " " + subjectives.get(Utilities.random.nextInt(subjectives.size()));
        return result2;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextSettingsCell.class, MryTextCheckCell.class, HeaderCell.class, BrightnessControlCell.class, ThemeTypeCell.class, TextSizeCell.class, ChatListCell.class, NotificationsCheckCell.class, ThemesHorizontalListCell.class, TintRecyclerListView.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUBACKGROUND, null, null, null, null, Theme.key_actionBarDefaultSubmenuBackground), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM, null, null, null, null, Theme.key_actionBarDefaultSubmenuItem), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM | ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_actionBarDefaultSubmenuItemIcon), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, 0, new Class[]{MryTextCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{MryTextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{MryTextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{BrightnessControlCell.class}, new String[]{"leftImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_profile_actionIcon), new ThemeDescription(this.listView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{BrightnessControlCell.class}, new String[]{"rightImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_profile_actionIcon), new ThemeDescription(this.listView, 0, new Class[]{BrightnessControlCell.class}, new String[]{"seekBarView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_player_progressBackground), new ThemeDescription(this.listView, ThemeDescription.FLAG_PROGRESSBAR, new Class[]{BrightnessControlCell.class}, new String[]{"seekBarView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_player_progress), new ThemeDescription(this.listView, 0, new Class[]{ThemeTypeCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{ThemeTypeCell.class}, new String[]{"checkImage"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_featuredStickers_addedIcon), new ThemeDescription(this.listView, ThemeDescription.FLAG_PROGRESSBAR, new Class[]{TextSizeCell.class}, new String[]{"sizeBar"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_player_progress), new ThemeDescription(this.listView, 0, new Class[]{TextSizeCell.class}, new String[]{"sizeBar"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_player_progressBackground), new ThemeDescription(this.listView, 0, new Class[]{ChatListCell.class}, null, null, null, Theme.key_radioBackground), new ThemeDescription(this.listView, 0, new Class[]{ChatListCell.class}, null, null, null, Theme.key_radioBackgroundChecked), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{NotificationsCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgInDrawable, Theme.chat_msgInMediaDrawable}, null, Theme.key_chat_inBubble), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgInSelectedDrawable, Theme.chat_msgInMediaSelectedDrawable}, null, Theme.key_chat_inBubbleSelected), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgInShadowDrawable, Theme.chat_msgInMediaShadowDrawable}, null, Theme.key_chat_inBubbleShadow), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutDrawable, Theme.chat_msgOutMediaDrawable}, null, Theme.key_chat_outBubble), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutSelectedDrawable, Theme.chat_msgOutMediaSelectedDrawable}, null, Theme.key_chat_outBubbleSelected), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutShadowDrawable, Theme.chat_msgOutMediaShadowDrawable}, null, Theme.key_chat_outBubbleShadow), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_messageTextIn), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_messageTextOut), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutCheckDrawable}, null, Theme.key_chat_outSentCheck), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutCheckSelectedDrawable}, null, Theme.key_chat_outSentCheckSelected), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutCheckReadDrawable, Theme.chat_msgOutHalfCheckDrawable}, null, Theme.key_chat_outSentCheckRead), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgOutCheckReadSelectedDrawable, Theme.chat_msgOutHalfCheckSelectedDrawable}, null, Theme.key_chat_outSentCheckReadSelected), new ThemeDescription(this.listView, 0, null, null, new Drawable[]{Theme.chat_msgMediaCheckDrawable, Theme.chat_msgMediaHalfCheckDrawable}, null, Theme.key_chat_mediaSentCheck), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inReplyLine), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outReplyLine), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inReplyNameText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outReplyNameText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inReplyMessageText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outReplyMessageText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inReplyMediaMessageSelectedText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outReplyMediaMessageSelectedText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inTimeText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outTimeText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_inTimeSelectedText), new ThemeDescription(this.listView, 0, null, null, null, null, Theme.key_chat_outTimeSelectedText)};
    }
}
