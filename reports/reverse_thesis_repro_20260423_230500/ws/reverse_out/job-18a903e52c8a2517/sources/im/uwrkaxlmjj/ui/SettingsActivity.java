package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Property;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;
import android.view.ViewTreeObserver;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.SPConstant;
import com.king.zxing.util.CodeUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.EmptyCell;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.SettingsSearchCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCell;
import im.uwrkaxlmjj.ui.cells.TextDetailCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.ImageUpdater;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;
import im.uwrkaxlmjj.ui.hui.discovery.ActionIntroActivity;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import im.uwrkaxlmjj.ui.settings.NoticeAndSoundSettingActivity;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import mpEIGo.juqQQs.esbSDO.R;
import okhttp3.internal.http.StatusLine;
import org.slf4j.Marker;
import org.xmlpull.v1.XmlPullParserException;

/* JADX INFO: loaded from: classes5.dex */
@Deprecated
public class SettingsActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate, ImageUpdater.ImageUpdaterDelegate {
    private static final int edit_name = 1;
    private static final int logout = 2;
    private static final int search_button = 3;
    private TLRPC.FileLocation avatar;
    private AnimatorSet avatarAnimation;
    private TLRPC.FileLocation avatarBig;
    private FrameLayout avatarContainer;
    private AvatarDrawable avatarDrawable;
    private BackupImageView avatarImage;
    private View avatarOverlay;
    private RadialProgressView avatarProgressView;
    private int bioRow;
    private int chatRow;
    private int dataRow;
    private EmptyTextProgressView emptyView;
    private int extraHeight;
    private View extraHeightView;
    private int helpRow;
    private ImageUpdater imageUpdater;
    private int languageRow;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private TextView nameTextView;
    private int notificationRow;
    private int numberRow;
    private int numberSectionRow;
    private TextView onlineTextView;
    private ActionBarMenuItem otherItem;
    private int overscrollRow;
    private int privacyRow;
    private PhotoViewer.PhotoViewerProvider provider = new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.SettingsActivity.1
        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public PhotoViewer.PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
            TLRPC.User user;
            if (fileLocation != null && (user = MessagesController.getInstance(SettingsActivity.this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(SettingsActivity.this.currentAccount).getClientUserId()))) != null && user.photo != null && user.photo.photo_big != null) {
                TLRPC.FileLocation photoBig = user.photo.photo_big;
                if (photoBig.local_id == fileLocation.local_id && photoBig.volume_id == fileLocation.volume_id && photoBig.dc_id == fileLocation.dc_id) {
                    int[] coords = new int[2];
                    SettingsActivity.this.avatarImage.getLocationInWindow(coords);
                    PhotoViewer.PlaceProviderObject object = new PhotoViewer.PlaceProviderObject();
                    object.viewX = coords[0];
                    object.viewY = coords[1] - (Build.VERSION.SDK_INT < 21 ? AndroidUtilities.statusBarHeight : 0);
                    object.parentView = SettingsActivity.this.avatarImage;
                    object.imageReceiver = SettingsActivity.this.avatarImage.getImageReceiver();
                    object.dialogId = UserConfig.getInstance(SettingsActivity.this.currentAccount).getClientUserId();
                    object.thumb = object.imageReceiver.getBitmapSafe();
                    object.size = -1;
                    object.radius = SettingsActivity.this.avatarImage.getImageReceiver().getRoundRadius();
                    object.scale = SettingsActivity.this.avatarContainer.getScaleX();
                    return object;
                }
            }
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void willHidePhotoViewer() {
            SettingsActivity.this.avatarImage.getImageReceiver().setVisible(true, true);
        }
    };
    private int rowCount;
    private SearchAdapter searchAdapter;
    private int settingsSectionRow;
    private int settingsSectionRow2;
    private View shadowView;
    private TLRPC.UserFull userInfo;
    private int usernameRow;
    private int versionRow;
    private ImageView writeButton;
    private AnimatorSet writeButtonAnimation;

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public /* synthetic */ void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> arrayList, boolean z, int i) {
        ImageUpdater.ImageUpdaterDelegate.CC.$default$didSelectPhotos(this, arrayList, z, i);
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public /* synthetic */ String getInitialSearchString() {
        return ImageUpdater.ImageUpdaterDelegate.CC.$default$getInitialSearchString(this);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        ImageUpdater imageUpdater = new ImageUpdater();
        this.imageUpdater = imageUpdater;
        imageUpdater.parentFragment = this;
        this.imageUpdater.delegate = this;
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.overscrollRow = 0;
        int i2 = i + 1;
        this.rowCount = i2;
        this.numberSectionRow = i;
        int i3 = i2 + 1;
        this.rowCount = i3;
        this.numberRow = i2;
        int i4 = i3 + 1;
        this.rowCount = i4;
        this.usernameRow = i3;
        int i5 = i4 + 1;
        this.rowCount = i5;
        this.bioRow = i4;
        int i6 = i5 + 1;
        this.rowCount = i6;
        this.settingsSectionRow = i5;
        int i7 = i6 + 1;
        this.rowCount = i7;
        this.settingsSectionRow2 = i6;
        int i8 = i7 + 1;
        this.rowCount = i8;
        this.notificationRow = i7;
        int i9 = i8 + 1;
        this.rowCount = i9;
        this.privacyRow = i8;
        int i10 = i9 + 1;
        this.rowCount = i10;
        this.dataRow = i9;
        int i11 = i10 + 1;
        this.rowCount = i11;
        this.chatRow = i10;
        int i12 = i11 + 1;
        this.rowCount = i12;
        this.languageRow = i11;
        int i13 = i12 + 1;
        this.rowCount = i13;
        this.helpRow = i12;
        this.rowCount = i13 + 1;
        this.versionRow = i13;
        MediaDataController.getInstance(this.currentAccount).checkFeaturedStickers();
        this.userInfo = MessagesController.getInstance(this.currentAccount).getUserFull(UserConfig.getInstance(this.currentAccount).getClientUserId());
        MessagesController.getInstance(this.currentAccount).loadUserInfo(UserConfig.getInstance(this.currentAccount).getCurrentUser(), true, this.classGuid);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        BackupImageView backupImageView = this.avatarImage;
        if (backupImageView != null) {
            backupImageView.setImageDrawable(null);
        }
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
        this.imageUpdater.clear();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        int scrollTo;
        this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_avatar_backgroundActionBarBlue));
        boolean z = false;
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_avatar_actionBarSelectorBlue), false);
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_avatar_actionBarIconBlue), false);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAddToContainer(false);
        this.extraHeight = 88;
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.SettingsActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    SettingsActivity.this.finishFragment();
                } else if (id == 1) {
                    SettingsActivity.this.presentFragment(new ChangeNameActivity());
                } else if (id == 2) {
                    SettingsActivity.this.presentFragment(new LogoutActivity());
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        int i = 1;
        ActionBarMenuItem searchItem = menu.addItem(3, R.drawable.ic_ab_search).setIsSearchField(true).setActionBarMenuItemSearchListener(new ActionBarMenuItem.ActionBarMenuItemSearchListener() { // from class: im.uwrkaxlmjj.ui.SettingsActivity.3
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchExpand() {
                if (SettingsActivity.this.otherItem != null) {
                    SettingsActivity.this.otherItem.setVisibility(8);
                }
                SettingsActivity.this.searchAdapter.loadFaqWebPage();
                SettingsActivity.this.listView.setAdapter(SettingsActivity.this.searchAdapter);
                SettingsActivity.this.listView.setEmptyView(SettingsActivity.this.emptyView);
                SettingsActivity.this.avatarContainer.setVisibility(8);
                SettingsActivity.this.writeButton.setVisibility(8);
                SettingsActivity.this.nameTextView.setVisibility(8);
                SettingsActivity.this.onlineTextView.setVisibility(8);
                SettingsActivity.this.extraHeightView.setVisibility(8);
                SettingsActivity.this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                SettingsActivity.this.fragmentView.setTag(Theme.key_windowBackgroundWhite);
                SettingsActivity.this.needLayout();
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchCollapse() {
                if (SettingsActivity.this.otherItem != null) {
                    SettingsActivity.this.otherItem.setVisibility(0);
                }
                SettingsActivity.this.listView.setAdapter(SettingsActivity.this.listAdapter);
                SettingsActivity.this.listView.setEmptyView(null);
                SettingsActivity.this.emptyView.setVisibility(8);
                SettingsActivity.this.avatarContainer.setVisibility(0);
                SettingsActivity.this.writeButton.setVisibility(0);
                SettingsActivity.this.nameTextView.setVisibility(0);
                SettingsActivity.this.onlineTextView.setVisibility(0);
                SettingsActivity.this.extraHeightView.setVisibility(0);
                SettingsActivity.this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                SettingsActivity.this.fragmentView.setTag(Theme.key_windowBackgroundGray);
                SettingsActivity.this.needLayout();
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onTextChanged(EditText editText) {
                SettingsActivity.this.searchAdapter.search(editText.getText().toString().toLowerCase());
            }
        });
        searchItem.setContentDescription(LocaleController.getString("SearchInSettings", R.string.SearchInSettings));
        searchItem.setSearchFieldHint(LocaleController.getString("SearchInSettings", R.string.SearchInSettings));
        ActionBarMenuItem actionBarMenuItemAddItem = menu.addItem(0, R.drawable.ic_ab_other);
        this.otherItem = actionBarMenuItemAddItem;
        actionBarMenuItemAddItem.setContentDescription(LocaleController.getString("AccDescrMoreOptions", R.string.AccDescrMoreOptions));
        this.otherItem.addSubItem(1, R.drawable.msg_edit, LocaleController.getString("EditName", R.string.EditName));
        this.otherItem.addSubItem(2, R.drawable.msg_leave, LocaleController.getString("LogOut", R.string.LogOut));
        int scrollToPosition = 0;
        Object writeButtonTag = null;
        if (this.listView != null) {
            scrollTo = this.layoutManager.findFirstVisibleItemPosition();
            View topView = this.layoutManager.findViewByPosition(scrollTo);
            if (topView != null) {
                scrollToPosition = topView.getTop();
            } else {
                scrollTo = -1;
            }
            writeButtonTag = this.writeButton.getTag();
        } else {
            scrollTo = -1;
        }
        this.listAdapter = new ListAdapter(context);
        this.searchAdapter = new SearchAdapter(context);
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.fragmentView.setTag(Theme.key_windowBackgroundGray);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, i, z) { // from class: im.uwrkaxlmjj.ui.SettingsActivity.4
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        this.listView.setGlowColor(Theme.getColor(Theme.key_avatar_backgroundActionBarBlue));
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, 51));
        this.listView.setAdapter(this.listAdapter);
        this.listView.setItemAnimator(null);
        this.listView.setLayoutAnimation(null);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$sTBdSR-EgtQBbLxH_KhdEH-7yZs
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i2) {
                this.f$0.lambda$createView$0$SettingsActivity(view, i2);
            }
        });
        this.listView.setOnItemLongClickListener(new AnonymousClass5());
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.showTextView();
        this.emptyView.setTextSize(18);
        this.emptyView.setVisibility(8);
        this.emptyView.setShowAtCenter(true);
        frameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
        frameLayout.addView(this.actionBar);
        View view = new View(context);
        this.extraHeightView = view;
        view.setPivotY(0.0f);
        this.extraHeightView.setBackgroundColor(Theme.getColor(Theme.key_avatar_backgroundActionBarBlue));
        frameLayout.addView(this.extraHeightView, LayoutHelper.createFrame(-1, 88.0f));
        View view2 = new View(context);
        this.shadowView = view2;
        view2.setBackgroundResource(R.drawable.header_shadow);
        frameLayout.addView(this.shadowView, LayoutHelper.createFrame(-1, 3.0f));
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.avatarContainer = frameLayout2;
        frameLayout2.setPivotX(LocaleController.isRTL ? AndroidUtilities.dp(42.0f) : 0.0f);
        this.avatarContainer.setPivotY(0.0f);
        frameLayout.addView(this.avatarContainer, LayoutHelper.createFrame(42.0f, 42.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 0 : 64, 0.0f, LocaleController.isRTL ? 112 : 0, 0.0f));
        this.avatarContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$3QtFErmZiXKs0y5aEVh6mB-Y9aY
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$createView$1$SettingsActivity(view3);
            }
        });
        BackupImageView backupImageView = new BackupImageView(context);
        this.avatarImage = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(21.0f));
        this.avatarImage.setContentDescription(LocaleController.getString("AccDescrProfilePicture", R.string.AccDescrProfilePicture));
        this.avatarContainer.addView(this.avatarImage, LayoutHelper.createFrame(42, 42.0f));
        final Paint paint = new Paint(1);
        paint.setColor(1426063360);
        RadialProgressView radialProgressView = new RadialProgressView(context) { // from class: im.uwrkaxlmjj.ui.SettingsActivity.6
            @Override // im.uwrkaxlmjj.ui.components.RadialProgressView, android.view.View
            protected void onDraw(Canvas canvas) {
                if (SettingsActivity.this.avatarImage != null && SettingsActivity.this.avatarImage.getImageReceiver().hasNotThumb()) {
                    paint.setAlpha((int) (SettingsActivity.this.avatarImage.getImageReceiver().getCurrentAlpha() * 85.0f));
                    canvas.drawCircle(getMeasuredWidth() / 2, getMeasuredHeight() / 2, AndroidUtilities.dp(21.0f), paint);
                }
                super.onDraw(canvas);
            }
        };
        this.avatarProgressView = radialProgressView;
        radialProgressView.setSize(AndroidUtilities.dp(26.0f));
        this.avatarProgressView.setProgressColor(-1);
        this.avatarContainer.addView(this.avatarProgressView, LayoutHelper.createFrame(42, 42.0f));
        showAvatarProgress(false, false);
        TextView textView = new TextView(context) { // from class: im.uwrkaxlmjj.ui.SettingsActivity.7
            @Override // android.widget.TextView, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                setPivotX(LocaleController.isRTL ? getMeasuredWidth() : 0.0f);
            }
        };
        this.nameTextView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_profile_title));
        this.nameTextView.setTextSize(1, 18.0f);
        this.nameTextView.setLines(1);
        this.nameTextView.setMaxLines(1);
        this.nameTextView.setSingleLine(true);
        this.nameTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.nameTextView.setGravity(LocaleController.isRTL ? 5 : 3);
        this.nameTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.nameTextView.setPivotY(0.0f);
        frameLayout.addView(this.nameTextView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 48.0f : 118.0f, 0.0f, LocaleController.isRTL ? 166.0f : 96.0f, 0.0f));
        TextView textView2 = new TextView(context);
        this.onlineTextView = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_profile_status));
        this.onlineTextView.setTextSize(1, 14.0f);
        this.onlineTextView.setLines(1);
        this.onlineTextView.setMaxLines(1);
        this.onlineTextView.setSingleLine(true);
        this.onlineTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.onlineTextView.setGravity(LocaleController.isRTL ? 5 : 3);
        frameLayout.addView(this.onlineTextView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 48.0f : 118.0f, 0.0f, LocaleController.isRTL ? 166.0f : 96.0f, 0.0f));
        this.writeButton = new ImageView(context);
        Drawable drawable = Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(56.0f), Theme.getColor(Theme.key_profile_actionBackground), Theme.getColor(Theme.key_profile_actionPressedBackground));
        if (Build.VERSION.SDK_INT < 21) {
            Drawable shadowDrawable = context.getResources().getDrawable(R.drawable.floating_shadow_profile).mutate();
            shadowDrawable.setColorFilter(new PorterDuffColorFilter(-16777216, PorterDuff.Mode.MULTIPLY));
            CombinedDrawable combinedDrawable = new CombinedDrawable(shadowDrawable, drawable, 0, 0);
            combinedDrawable.setIconSize(AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
            drawable = combinedDrawable;
        }
        this.writeButton.setBackgroundDrawable(drawable);
        this.writeButton.setImageResource(R.drawable.menu_camera_av);
        this.writeButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_profile_actionIcon), PorterDuff.Mode.MULTIPLY));
        this.writeButton.setScaleType(ImageView.ScaleType.CENTER);
        if (Build.VERSION.SDK_INT >= 21) {
            StateListAnimator animator = new StateListAnimator();
            animator.addState(new int[]{android.R.attr.state_pressed}, ObjectAnimator.ofFloat(this.writeButton, "translationZ", AndroidUtilities.dp(2.0f), AndroidUtilities.dp(4.0f)).setDuration(200L));
            animator.addState(new int[0], ObjectAnimator.ofFloat(this.writeButton, "translationZ", AndroidUtilities.dp(4.0f), AndroidUtilities.dp(2.0f)).setDuration(200L));
            this.writeButton.setStateListAnimator(animator);
            this.writeButton.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.SettingsActivity.8
                @Override // android.view.ViewOutlineProvider
                public void getOutline(View view3, Outline outline) {
                    outline.setOval(0, 0, AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
                }
            });
        }
        frameLayout.addView(this.writeButton, LayoutHelper.createFrame(Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, (LocaleController.isRTL ? 3 : 5) | 48, LocaleController.isRTL ? 16.0f : 0.0f, 0.0f, LocaleController.isRTL ? 0.0f : 16.0f, 0.0f));
        this.writeButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$LgDFieE7JElVkvslD_qL-qZyYcY
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$createView$3$SettingsActivity(view3);
            }
        });
        this.writeButton.setContentDescription(LocaleController.getString("AccDescrChangeProfilePicture", R.string.AccDescrChangeProfilePicture));
        if (scrollTo != -1) {
            this.layoutManager.scrollToPositionWithOffset(scrollTo, scrollToPosition);
            if (writeButtonTag != null) {
                this.writeButton.setTag(0);
                this.writeButton.setScaleX(0.2f);
                this.writeButton.setScaleY(0.2f);
                this.writeButton.setAlpha(0.0f);
                this.writeButton.setVisibility(8);
            }
        }
        needLayout();
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.SettingsActivity.9
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1 && SettingsActivity.this.listView.getAdapter() == SettingsActivity.this.searchAdapter) {
                    AndroidUtilities.hideKeyboard(SettingsActivity.this.getParentActivity().getCurrentFocus());
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                if (SettingsActivity.this.layoutManager.getItemCount() == 0) {
                    return;
                }
                int height = 0;
                View child = recyclerView.getChildAt(0);
                if (child != null && SettingsActivity.this.avatarContainer.getVisibility() == 0) {
                    if (SettingsActivity.this.layoutManager.findFirstVisibleItemPosition() == 0) {
                        height = AndroidUtilities.dp(88.0f) + (child.getTop() < 0 ? child.getTop() : 0);
                    }
                    if (SettingsActivity.this.extraHeight != height) {
                        SettingsActivity.this.extraHeight = height;
                        SettingsActivity.this.needLayout();
                    }
                }
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$0$SettingsActivity(View view, int position) {
        if (this.listView.getAdapter() == this.listAdapter) {
            if (position == this.notificationRow) {
                presentFragment(new NoticeAndSoundSettingActivity());
                return;
            }
            if (position == this.privacyRow) {
                presentFragment(new PrivacySettingsActivity());
                return;
            }
            if (position == this.dataRow) {
                presentFragment(new DataSettingsActivity());
                return;
            }
            if (position == this.chatRow) {
                presentFragment(new ThemeActivity(0));
                return;
            }
            if (position == this.helpRow) {
                showHelpAlert();
                return;
            }
            if (position == this.languageRow) {
                presentFragment(new LanguageSelectActivity());
                return;
            }
            if (position == this.usernameRow) {
                presentFragment(new ChangeUsernameActivity());
                return;
            }
            if (position == this.bioRow) {
                if (this.userInfo != null) {
                    presentFragment(new ChangeBioActivity());
                    return;
                }
                return;
            } else {
                if (position == this.numberRow) {
                    presentFragment(new ActionIntroActivity(3));
                    return;
                }
                return;
            }
        }
        if (position < 0) {
            return;
        }
        Object object = Integer.valueOf(this.numberRow);
        if (!this.searchAdapter.searchWas) {
            int position2 = position - 1;
            if (position2 < 0) {
                return;
            }
            if (position2 < this.searchAdapter.recentSearches.size()) {
                object = this.searchAdapter.recentSearches.get(position2);
            }
        } else if (position < this.searchAdapter.searchResults.size()) {
            object = this.searchAdapter.searchResults.get(position);
        } else {
            int position3 = position - (this.searchAdapter.searchResults.size() + 1);
            if (position3 >= 0 && position3 < this.searchAdapter.faqSearchResults.size()) {
                object = this.searchAdapter.faqSearchResults.get(position3);
            }
        }
        if (object instanceof SearchAdapter.SearchResult) {
            SearchAdapter.SearchResult result = (SearchAdapter.SearchResult) object;
            result.open();
        } else if (object instanceof SearchAdapter.FaqSearchResult) {
            SearchAdapter.FaqSearchResult result2 = (SearchAdapter.FaqSearchResult) object;
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.openArticle, this.searchAdapter.faqWebPage, result2.url);
        }
        if (object != null) {
            this.searchAdapter.addRecent(object);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.SettingsActivity$5, reason: invalid class name */
    class AnonymousClass5 implements RecyclerListView.OnItemLongClickListener {
        private int pressCount = 0;

        AnonymousClass5() {
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
        public boolean onItemClick(View view, int position) {
            int i;
            String str;
            int i2;
            String str2;
            if (SettingsActivity.this.listView.getAdapter() != SettingsActivity.this.searchAdapter) {
                if (position != SettingsActivity.this.versionRow) {
                    return false;
                }
                int i3 = this.pressCount + 1;
                this.pressCount = i3;
                if (i3 >= 2 || BuildVars.DEBUG_PRIVATE_VERSION) {
                    AlertDialog.Builder builder = new AlertDialog.Builder(SettingsActivity.this.getParentActivity());
                    builder.setTitle(LocaleController.getString("DebugMenu", R.string.DebugMenu));
                    CharSequence[] items = new CharSequence[11];
                    items[0] = LocaleController.getString("DebugMenuImportContacts", R.string.DebugMenuImportContacts);
                    items[1] = LocaleController.getString("DebugMenuReloadContacts", R.string.DebugMenuReloadContacts);
                    items[2] = LocaleController.getString("DebugMenuResetContacts", R.string.DebugMenuResetContacts);
                    items[3] = LocaleController.getString("DebugMenuResetDialogs", R.string.DebugMenuResetDialogs);
                    if (BuildVars.LOGS_ENABLED) {
                        i = R.string.DebugMenuDisableLogs;
                        str = "DebugMenuDisableLogs";
                    } else {
                        i = R.string.DebugMenuEnableLogs;
                        str = "DebugMenuEnableLogs";
                    }
                    items[4] = LocaleController.getString(str, i);
                    if (SharedConfig.inappCamera) {
                        i2 = R.string.DebugMenuDisableCamera;
                        str2 = "DebugMenuDisableCamera";
                    } else {
                        i2 = R.string.DebugMenuEnableCamera;
                        str2 = "DebugMenuEnableCamera";
                    }
                    items[5] = LocaleController.getString(str2, i2);
                    items[6] = LocaleController.getString("DebugMenuClearMediaCache", R.string.DebugMenuClearMediaCache);
                    items[7] = LocaleController.getString("DebugMenuCallSettings", R.string.DebugMenuCallSettings);
                    items[8] = null;
                    items[9] = BuildVars.DEBUG_PRIVATE_VERSION ? "Check for app updates" : null;
                    items[10] = LocaleController.getString("DebugMenuReadAllDialogs", R.string.DebugMenuReadAllDialogs);
                    builder.setItems(items, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$5$UQP9rZFpV2D-vMpWxtk875EtVzs
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i4) {
                            this.f$0.lambda$onItemClick$1$SettingsActivity$5(dialogInterface, i4);
                        }
                    });
                    builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                    SettingsActivity.this.showDialog(builder.create());
                } else {
                    ToastUtils.show((CharSequence) "¯\\_(ツ)_/¯");
                }
                return true;
            }
            AlertDialog.Builder builder2 = new AlertDialog.Builder(SettingsActivity.this.getParentActivity());
            builder2.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder2.setMessage(LocaleController.getString("ClearSearch", R.string.ClearSearch));
            builder2.setPositiveButton(LocaleController.getString("ClearButton", R.string.ClearButton).toUpperCase(), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$5$e9Sut7Z4uEdw0snfy3OE4cBWcgI
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i4) {
                    this.f$0.lambda$onItemClick$0$SettingsActivity$5(dialogInterface, i4);
                }
            });
            builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            SettingsActivity.this.showDialog(builder2.create());
            return true;
        }

        public /* synthetic */ void lambda$onItemClick$0$SettingsActivity$5(DialogInterface dialogInterface, int i) {
            SettingsActivity.this.searchAdapter.clearRecent();
        }

        public /* synthetic */ void lambda$onItemClick$1$SettingsActivity$5(DialogInterface dialog, int which) {
            if (which == 0) {
                UserConfig.getInstance(SettingsActivity.this.currentAccount).syncContacts = true;
                UserConfig.getInstance(SettingsActivity.this.currentAccount).saveConfig(false);
                ContactsController.getInstance(SettingsActivity.this.currentAccount).forceImportContacts();
                return;
            }
            if (which == 1) {
                ContactsController.getInstance(SettingsActivity.this.currentAccount).loadContacts(false, 0);
                return;
            }
            if (which == 2) {
                ContactsController.getInstance(SettingsActivity.this.currentAccount).resetImportedContacts();
                return;
            }
            if (which == 3) {
                MessagesController.getInstance(SettingsActivity.this.currentAccount).forceResetDialogs();
                return;
            }
            if (which == 4) {
                BuildVars.LOGS_ENABLED = true ^ BuildVars.LOGS_ENABLED;
                SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences(SPConstant.SP_SYSTEM_CONFIG, 0);
                sharedPreferences.edit().putBoolean("logsEnabled", BuildVars.LOGS_ENABLED).commit();
                return;
            }
            if (which == 5) {
                SharedConfig.toggleInappCamera();
                return;
            }
            if (which == 6) {
                MessagesStorage.getInstance(SettingsActivity.this.currentAccount).clearSentMedia();
                SharedConfig.setNoSoundHintShowed(false);
                SharedPreferences.Editor editor = MessagesController.getGlobalMainSettings().edit();
                editor.remove("archivehint").remove("archivehint_l").remove("gifhint").remove("soundHint").commit();
                return;
            }
            if (which == 7) {
                VoIPHelper.showCallDebugSettings(SettingsActivity.this.getParentActivity());
                return;
            }
            if (which == 8) {
                SharedConfig.toggleRoundCamera16to9();
            } else if (which == 9) {
                ((LaunchActivity) SettingsActivity.this.getParentActivity()).checkAppUpdate(true);
            } else if (which == 10) {
                MessagesStorage.getInstance(SettingsActivity.this.currentAccount).readAllDialogs();
            }
        }
    }

    public /* synthetic */ void lambda$createView$1$SettingsActivity(View v) {
        TLRPC.User user;
        if (this.avatar == null && (user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()))) != null && user.photo != null && user.photo.photo_big != null) {
            PhotoViewer.getInstance().setParentActivity(getParentActivity());
            if (user.photo.dc_id != 0) {
                user.photo.photo_big.dc_id = user.photo.dc_id;
            }
            PhotoViewer.getInstance().openPhoto(user.photo.photo_big, this.provider);
        }
    }

    public /* synthetic */ void lambda$createView$3$SettingsActivity(View v) {
        TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()));
        if (user == null) {
            user = UserConfig.getInstance(this.currentAccount).getCurrentUser();
        }
        if (user == null) {
            return;
        }
        this.imageUpdater.openMenu((user.photo == null || user.photo.photo_big == null || (user.photo instanceof TLRPC.TL_userProfilePhotoEmpty)) ? false : true, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$4bV_Qk_pZ04VU_kPBKz67IE9Pqs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$SettingsActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$2$SettingsActivity() {
        MessagesController.getInstance(this.currentAccount).deleteUserPhoto(null);
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public void didUploadPhoto(final TLRPC.InputFile file, final TLRPC.PhotoSize bigSize, final TLRPC.PhotoSize smallSize) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$XR6V14W13ssaUwvHjJ8egXq1Buc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$didUploadPhoto$6$SettingsActivity(file, smallSize, bigSize);
            }
        });
    }

    public /* synthetic */ void lambda$didUploadPhoto$6$SettingsActivity(TLRPC.InputFile file, TLRPC.PhotoSize smallSize, TLRPC.PhotoSize bigSize) {
        if (file != null) {
            TLRPC.TL_photos_uploadProfilePhoto req = new TLRPC.TL_photos_uploadProfilePhoto();
            req.file = file;
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$b-UA19YqUblpDAMm3K_ZVRCW2l8
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$5$SettingsActivity(tLObject, tL_error);
                }
            });
        } else {
            this.avatar = smallSize.location;
            this.avatarBig = bigSize.location;
            this.avatarImage.setImage(ImageLocation.getForLocal(this.avatar), "50_50", this.avatarDrawable, (Object) null);
            showAvatarProgress(true, false);
        }
    }

    public /* synthetic */ void lambda$null$5$SettingsActivity(TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()));
            if (user == null) {
                user = UserConfig.getInstance(this.currentAccount).getCurrentUser();
                if (user != null) {
                    MessagesController.getInstance(this.currentAccount).putUser(user, false);
                } else {
                    return;
                }
            } else {
                UserConfig.getInstance(this.currentAccount).setCurrentUser(user);
            }
            TLRPC.TL_photos_photo photo = (TLRPC.TL_photos_photo) response;
            ArrayList<TLRPC.PhotoSize> sizes = photo.photo.sizes;
            TLRPC.PhotoSize small = FileLoader.getClosestPhotoSizeWithSize(sizes, 150);
            TLRPC.PhotoSize big = FileLoader.getClosestPhotoSizeWithSize(sizes, CodeUtils.DEFAULT_REQ_HEIGHT);
            user.photo = new TLRPC.TL_userProfilePhoto();
            user.photo.photo_id = photo.photo.id;
            if (small != null) {
                user.photo.photo_small = small.location;
            }
            if (big != null) {
                user.photo.photo_big = big.location;
            } else if (small != null) {
                user.photo.photo_small = small.location;
            }
            if (photo != null) {
                if (small != null && this.avatar != null) {
                    File destFile = FileLoader.getPathToAttach(small, true);
                    File src = FileLoader.getPathToAttach(this.avatar, true);
                    src.renameTo(destFile);
                    String oldKey = this.avatar.volume_id + "_" + this.avatar.local_id + "@50_50";
                    String newKey = small.location.volume_id + "_" + small.location.local_id + "@50_50";
                    ImageLoader.getInstance().replaceImageInCache(oldKey, newKey, ImageLocation.getForUser(user, false), true);
                }
                if (big != null && this.avatarBig != null) {
                    File destFile2 = FileLoader.getPathToAttach(big, true);
                    File src2 = FileLoader.getPathToAttach(this.avatarBig, true);
                    src2.renameTo(destFile2);
                }
            }
            MessagesStorage.getInstance(this.currentAccount).clearUserPhotos(user.id);
            ArrayList<TLRPC.User> users = new ArrayList<>();
            users.add(user);
            MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(users, null, false, true);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$QnLsYaY_tccNXe5fLF3LZ60D4ow
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$4$SettingsActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$4$SettingsActivity() {
        this.avatar = null;
        this.avatarBig = null;
        updateUserData();
        showAvatarProgress(false, true);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.updateInterfaces, Integer.valueOf(MessagesController.UPDATE_MASK_ALL));
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
        UserConfig.getInstance(this.currentAccount).saveConfig(true);
    }

    private void showAvatarProgress(final boolean show, boolean animated) {
        if (this.avatarProgressView == null) {
            return;
        }
        AnimatorSet animatorSet = this.avatarAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.avatarAnimation = null;
        }
        if (animated) {
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.avatarAnimation = animatorSet2;
            if (show) {
                this.avatarProgressView.setVisibility(0);
                this.avatarAnimation.playTogether(ObjectAnimator.ofFloat(this.avatarProgressView, (Property<RadialProgressView, Float>) View.ALPHA, 1.0f));
            } else {
                animatorSet2.playTogether(ObjectAnimator.ofFloat(this.avatarProgressView, (Property<RadialProgressView, Float>) View.ALPHA, 0.0f));
            }
            this.avatarAnimation.setDuration(180L);
            this.avatarAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.SettingsActivity.10
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (SettingsActivity.this.avatarAnimation == null || SettingsActivity.this.avatarProgressView == null) {
                        return;
                    }
                    if (!show) {
                        SettingsActivity.this.avatarProgressView.setVisibility(4);
                    }
                    SettingsActivity.this.avatarAnimation = null;
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    SettingsActivity.this.avatarAnimation = null;
                }
            });
            this.avatarAnimation.start();
            return;
        }
        if (show) {
            this.avatarProgressView.setAlpha(1.0f);
            this.avatarProgressView.setVisibility(0);
        } else {
            this.avatarProgressView.setAlpha(0.0f);
            this.avatarProgressView.setVisibility(4);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) throws FileNotFoundException {
        this.imageUpdater.onActivityResult(requestCode, resultCode, data);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle args) {
        ImageUpdater imageUpdater = this.imageUpdater;
        if (imageUpdater != null && imageUpdater.currentPicturePath != null) {
            args.putString("path", this.imageUpdater.currentPicturePath);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void restoreSelfArgs(Bundle args) {
        ImageUpdater imageUpdater = this.imageUpdater;
        if (imageUpdater != null) {
            imageUpdater.currentPicturePath = args.getString("path");
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        RecyclerListView recyclerListView;
        ListAdapter listAdapter;
        if (id == NotificationCenter.updateInterfaces) {
            int mask = ((Integer) args[0]).intValue();
            if ((mask & 2) != 0 || (mask & 1) != 0) {
                updateUserData();
                return;
            }
            return;
        }
        if (id == NotificationCenter.userFullInfoDidLoad) {
            Integer uid = (Integer) args[0];
            if (uid.intValue() == UserConfig.getInstance(this.currentAccount).getClientUserId() && (listAdapter = this.listAdapter) != null) {
                this.userInfo = (TLRPC.UserFull) args[1];
                listAdapter.notifyItemChanged(this.bioRow);
                return;
            }
            return;
        }
        if (id == NotificationCenter.emojiDidLoad && (recyclerListView = this.listView) != null) {
            recyclerListView.invalidateViews();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        updateUserData();
        fixLayout();
        setParentActivityTitle(LocaleController.getString("Settings", R.string.Settings));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        fixLayout();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void needLayout() {
        int currentExtraHeight;
        int newTop = (this.actionBar.getOccupyStatusBar() ? AndroidUtilities.statusBarHeight : 0) + ActionBar.getCurrentActionBarHeight();
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) recyclerListView.getLayoutParams();
            if (layoutParams.topMargin != newTop) {
                layoutParams.topMargin = newTop;
                this.listView.setLayoutParams(layoutParams);
                this.extraHeightView.setTranslationY(newTop);
            }
            FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.emptyView.getLayoutParams();
            if (layoutParams2.topMargin != newTop) {
                layoutParams2.topMargin = newTop;
                this.emptyView.setLayoutParams(layoutParams2);
            }
        }
        FrameLayout frameLayout = this.avatarContainer;
        if (frameLayout != null) {
            if (frameLayout.getVisibility() == 0) {
                currentExtraHeight = this.extraHeight;
            } else {
                currentExtraHeight = 0;
            }
            float diff = currentExtraHeight / AndroidUtilities.dp(88.0f);
            this.extraHeightView.setScaleY(diff);
            this.shadowView.setTranslationY(newTop + currentExtraHeight);
            this.writeButton.setTranslationY((((this.actionBar.getOccupyStatusBar() ? AndroidUtilities.statusBarHeight : 0) + ActionBar.getCurrentActionBarHeight()) + currentExtraHeight) - AndroidUtilities.dp(29.5f));
            final boolean setVisible = diff > 0.2f;
            boolean currentVisible = this.writeButton.getTag() == null;
            if (setVisible != currentVisible) {
                if (setVisible) {
                    this.writeButton.setTag(null);
                    this.writeButton.setVisibility(0);
                } else {
                    this.writeButton.setTag(0);
                }
                if (this.writeButtonAnimation != null) {
                    AnimatorSet old = this.writeButtonAnimation;
                    this.writeButtonAnimation = null;
                    old.cancel();
                }
                AnimatorSet animatorSet = new AnimatorSet();
                this.writeButtonAnimation = animatorSet;
                if (setVisible) {
                    animatorSet.setInterpolator(new DecelerateInterpolator());
                    this.writeButtonAnimation.playTogether(ObjectAnimator.ofFloat(this.writeButton, "scaleX", 1.0f), ObjectAnimator.ofFloat(this.writeButton, "scaleY", 1.0f), ObjectAnimator.ofFloat(this.writeButton, "alpha", 1.0f));
                } else {
                    animatorSet.setInterpolator(new AccelerateInterpolator());
                    this.writeButtonAnimation.playTogether(ObjectAnimator.ofFloat(this.writeButton, "scaleX", 0.2f), ObjectAnimator.ofFloat(this.writeButton, "scaleY", 0.2f), ObjectAnimator.ofFloat(this.writeButton, "alpha", 0.0f));
                }
                this.writeButtonAnimation.setDuration(150L);
                this.writeButtonAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.SettingsActivity.11
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (SettingsActivity.this.writeButtonAnimation != null && SettingsActivity.this.writeButtonAnimation.equals(animation)) {
                            SettingsActivity.this.writeButton.setVisibility(setVisible ? 0 : 8);
                            SettingsActivity.this.writeButtonAnimation = null;
                        }
                    }
                });
                this.writeButtonAnimation.start();
            }
            this.avatarContainer.setScaleX(((diff * 18.0f) + 42.0f) / 42.0f);
            this.avatarContainer.setScaleY(((18.0f * diff) + 42.0f) / 42.0f);
            this.avatarProgressView.setSize(AndroidUtilities.dp(26.0f / this.avatarContainer.getScaleX()));
            this.avatarProgressView.setStrokeWidth(3.0f / this.avatarContainer.getScaleX());
            float avatarY = (((this.actionBar.getOccupyStatusBar() ? AndroidUtilities.statusBarHeight : 0) + ((ActionBar.getCurrentActionBarHeight() / 2.0f) * (diff + 1.0f))) - (AndroidUtilities.density * 21.0f)) + (AndroidUtilities.density * 27.0f * diff);
            this.avatarContainer.setTranslationY((float) Math.ceil(avatarY));
            this.nameTextView.setTranslationY((((float) Math.floor(avatarY)) - ((float) Math.ceil(AndroidUtilities.density))) + ((float) Math.floor(AndroidUtilities.density * 7.0f * diff)));
            this.onlineTextView.setTranslationY(((float) Math.floor(avatarY)) + AndroidUtilities.dp(22.0f) + (((float) Math.floor(AndroidUtilities.density * 11.0f)) * diff));
            this.nameTextView.setScaleX((diff * 0.12f) + 1.0f);
            this.nameTextView.setScaleY((0.12f * diff) + 1.0f);
            if (LocaleController.isRTL) {
                this.avatarContainer.setTranslationX(AndroidUtilities.dp(95.0f) * diff);
                this.nameTextView.setTranslationX(AndroidUtilities.density * 69.0f * diff);
                this.onlineTextView.setTranslationX(AndroidUtilities.density * 69.0f * diff);
            } else {
                this.avatarContainer.setTranslationX((-AndroidUtilities.dp(47.0f)) * diff);
                this.nameTextView.setTranslationX(AndroidUtilities.density * (-21.0f) * diff);
                this.onlineTextView.setTranslationX(AndroidUtilities.density * (-21.0f) * diff);
            }
        }
    }

    private void fixLayout() {
        if (this.fragmentView == null) {
            return;
        }
        this.fragmentView.getViewTreeObserver().addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() { // from class: im.uwrkaxlmjj.ui.SettingsActivity.12
            @Override // android.view.ViewTreeObserver.OnPreDrawListener
            public boolean onPreDraw() {
                if (SettingsActivity.this.fragmentView != null) {
                    SettingsActivity.this.needLayout();
                    SettingsActivity.this.fragmentView.getViewTreeObserver().removeOnPreDrawListener(this);
                    return true;
                }
                return true;
            }
        });
    }

    private void updateUserData() {
        TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()));
        if (user == null) {
            return;
        }
        TLRPC.FileLocation photoBig = null;
        if (user.photo != null) {
            photoBig = user.photo.photo_big;
        }
        AvatarDrawable avatarDrawable = new AvatarDrawable(user, true);
        this.avatarDrawable = avatarDrawable;
        avatarDrawable.setColor(Theme.getColor(Theme.key_avatar_backgroundInProfileBlue));
        BackupImageView backupImageView = this.avatarImage;
        if (backupImageView != null) {
            backupImageView.setImage(ImageLocation.getForUser(user, false), "50_50", this.avatarDrawable, user);
            this.avatarImage.getImageReceiver().setVisible(!PhotoViewer.isShowingImage(photoBig), false);
            this.nameTextView.setText(UserObject.getName(user));
            this.onlineTextView.setText(LocaleController.getString("Online", R.string.Online));
            this.avatarImage.getImageReceiver().setVisible(true ^ PhotoViewer.isShowingImage(photoBig), false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showHelpAlert() {
        String text;
        if (getParentActivity() == null) {
            return;
        }
        Context context = getParentActivity();
        final BottomSheet.Builder builder = new BottomSheet.Builder(context);
        builder.setApplyTopPadding(false);
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setOrientation(1);
        HeaderCell headerCell = new HeaderCell(context, true, 23, 15, false);
        headerCell.setHeight(47);
        headerCell.setText(LocaleController.getString("SettingsHelp", R.string.SettingsHelp));
        linearLayout.addView(headerCell);
        LinearLayout linearLayoutInviteContainer = new LinearLayout(context);
        linearLayoutInviteContainer.setOrientation(1);
        linearLayout.addView(linearLayoutInviteContainer, LayoutHelper.createLinear(-1, -2));
        int a = 0;
        while (a < 6) {
            if ((a < 3 || a > 4 || BuildVars.LOGS_ENABLED) && (a != 5 || BuildVars.DEBUG_VERSION)) {
                TextCell textCell = new TextCell(context);
                if (a != 0) {
                    if (a != 1) {
                        if (a == 2) {
                            text = LocaleController.getString("PrivacyPolicy", R.string.PrivacyPolicy);
                        } else if (a != 3) {
                            if (a == 4) {
                                text = LocaleController.getString("DebugClearLogs", R.string.DebugClearLogs);
                            } else {
                                text = "Switch Backend";
                            }
                        } else {
                            text = LocaleController.getString("DebugSendLogs", R.string.DebugSendLogs);
                        }
                    } else {
                        text = LocaleController.getString("AppFaq", R.string.AppFaq);
                    }
                } else {
                    text = LocaleController.getString("AskAQuestion", R.string.AskAQuestion);
                }
                textCell.setText(text, BuildVars.LOGS_ENABLED || BuildVars.DEBUG_VERSION ? a != 6 + (-1) : a != 2);
                textCell.setTag(Integer.valueOf(a));
                textCell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
                linearLayoutInviteContainer.addView(textCell, LayoutHelper.createLinear(-1, -2));
                textCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$ZsiK3-e5QBzcxGkKI0SC25zSEFM
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$showHelpAlert$8$SettingsActivity(builder, view);
                    }
                });
            }
            a++;
        }
        builder.setCustomView(linearLayout);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$showHelpAlert$8$SettingsActivity(BottomSheet.Builder builder, View v2) {
        Integer tag = (Integer) v2.getTag();
        int iIntValue = tag.intValue();
        if (iIntValue == 0) {
            showDialog(AlertsCreator.createSupportAlert(this));
        } else if (iIntValue == 1) {
            Browser.openUrl(getParentActivity(), LocaleController.getString("AppFaqUrl", R.string.AppFaqUrl));
        } else if (iIntValue == 2) {
            Browser.openUrl(getParentActivity(), LocaleController.getString("PrivacyPolicyUrl", R.string.PrivacyPolicyUrl));
        } else if (iIntValue == 3) {
            sendLogs();
        } else if (iIntValue == 4) {
            FileLog.cleanupLogs();
        } else if (iIntValue == 5) {
            if (getParentActivity() == null) {
                return;
            }
            AlertDialog.Builder builder1 = new AlertDialog.Builder(getParentActivity());
            builder1.setMessage(LocaleController.getString("AreYouSure", R.string.AreYouSure));
            builder1.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder1.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$iy_vBiaqIte0m8OALms9xK-WGc0
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$7$SettingsActivity(dialogInterface, i);
                }
            });
            builder1.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder1.create());
        }
        builder.getDismissRunnable().run();
    }

    public /* synthetic */ void lambda$null$7$SettingsActivity(DialogInterface dialogInterface, int i) {
        SharedConfig.pushAuthKey = null;
        SharedConfig.pushAuthKeyId = null;
        SharedConfig.saveConfig();
        ConnectionsManager.getInstance(this.currentAccount).switchBackend();
    }

    private void sendLogs() {
        if (getParentActivity() == null) {
            return;
        }
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setCanCancel(false);
        progressDialog.show();
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$3gUr2nARqvrxy1S_s9Ti9y-WwJo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$sendLogs$10$SettingsActivity(progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$sendLogs$10$SettingsActivity(final AlertDialog progressDialog) {
        try {
            File sdCard = ApplicationLoader.applicationContext.getExternalFilesDir(null);
            File dir = new File(sdCard.getAbsolutePath() + "/logs");
            final File zipFile = new File(dir, "logs.zip");
            if (zipFile.exists()) {
                zipFile.delete();
            }
            File[] files = dir.listFiles();
            final boolean[] finished = new boolean[1];
            BufferedInputStream origin = null;
            ZipOutputStream out = null;
            try {
                try {
                    try {
                        FileOutputStream dest = new FileOutputStream(zipFile);
                        out = new ZipOutputStream(new BufferedOutputStream(dest));
                        byte[] data = new byte[65536];
                        for (int i = 0; i < files.length; i++) {
                            FileInputStream fi = new FileInputStream(files[i]);
                            BufferedInputStream origin2 = new BufferedInputStream(fi, data.length);
                            ZipEntry entry = new ZipEntry(files[i].getName());
                            out.putNextEntry(entry);
                            while (true) {
                                int count = origin2.read(data, 0, data.length);
                                if (count != -1) {
                                    out.write(data, 0, count);
                                }
                            }
                            origin2.close();
                            origin = null;
                        }
                        finished[0] = true;
                        if (origin != null) {
                            origin.close();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        if (origin != null) {
                            origin.close();
                        }
                        if (out != null) {
                        }
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$FoOotfGCYbAlam6SxhFbpJJld10
                            @Override // java.lang.Runnable
                            public final void run() throws XmlPullParserException, IOException {
                                this.f$0.lambda$null$9$SettingsActivity(progressDialog, finished, zipFile);
                            }
                        });
                    }
                    out.close();
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$FoOotfGCYbAlam6SxhFbpJJld10
                        @Override // java.lang.Runnable
                        public final void run() throws XmlPullParserException, IOException {
                            this.f$0.lambda$null$9$SettingsActivity(progressDialog, finished, zipFile);
                        }
                    });
                } catch (Throwable th) {
                    if (origin != null) {
                        origin.close();
                    }
                    if (out != null) {
                        out.close();
                    }
                    throw th;
                }
            } catch (Exception e2) {
                e = e2;
                e.printStackTrace();
            }
        } catch (Exception e3) {
            e = e3;
        }
    }

    public /* synthetic */ void lambda$null$9$SettingsActivity(AlertDialog progressDialog, boolean[] finished, File zipFile) throws XmlPullParserException, IOException {
        Uri uri;
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
        }
        if (finished[0]) {
            if (Build.VERSION.SDK_INT >= 24) {
                uri = FileProvider.getUriForFile(getParentActivity(), "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", zipFile);
            } else {
                uri = Uri.fromFile(zipFile);
            }
            Intent i = new Intent("android.intent.action.SEND");
            if (Build.VERSION.SDK_INT >= 24) {
                i.addFlags(1);
            }
            i.setType("message/rfc822");
            i.putExtra("android.intent.extra.EMAIL", "");
            i.putExtra("android.intent.extra.SUBJECT", "Logs from " + LocaleController.getInstance().formatterStats.format(System.currentTimeMillis()));
            i.putExtra("android.intent.extra.STREAM", uri);
            getParentActivity().startActivityForResult(Intent.createChooser(i, "Select email application."), SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
            return;
        }
        ToastUtils.show(R.string.ErrorOccurred);
    }

    /* JADX INFO: Access modifiers changed from: private */
    class SearchAdapter extends RecyclerListView.SelectionAdapter {
        private ArrayList<FaqSearchResult> faqSearchArray;
        private ArrayList<FaqSearchResult> faqSearchResults;
        private TLRPC.WebPage faqWebPage;
        private String lastSearchString;
        private boolean loadingFaqPage;
        private Context mContext;
        private ArrayList<Object> recentSearches;
        private ArrayList<CharSequence> resultNames;
        private SearchResult[] searchArray;
        private ArrayList<SearchResult> searchResults;
        private Runnable searchRunnable;
        private boolean searchWas;

        /* JADX INFO: Access modifiers changed from: private */
        class SearchResult {
            private int guid;
            private int iconResId;
            private int num;
            private Runnable openRunnable;
            private String[] path;
            private String rowName;
            private String searchTitle;

            public SearchResult(SearchAdapter searchAdapter, int g, String search, int icon, Runnable open) {
                this(g, search, null, null, null, icon, open);
            }

            public SearchResult(SearchAdapter searchAdapter, int g, String search, String pathArg1, int icon, Runnable open) {
                this(g, search, null, pathArg1, null, icon, open);
            }

            public SearchResult(SearchAdapter searchAdapter, int g, String search, String row, String pathArg1, int icon, Runnable open) {
                this(g, search, row, pathArg1, null, icon, open);
            }

            public SearchResult(int g, String search, String row, String pathArg1, String pathArg2, int icon, Runnable open) {
                this.guid = g;
                this.searchTitle = search;
                this.rowName = row;
                this.openRunnable = open;
                this.iconResId = icon;
                if (pathArg1 != null && pathArg2 != null) {
                    this.path = new String[]{pathArg1, pathArg2};
                } else if (pathArg1 != null) {
                    this.path = new String[]{pathArg1};
                }
            }

            public boolean equals(Object obj) {
                if (!(obj instanceof SearchResult)) {
                    return false;
                }
                SearchResult result = (SearchResult) obj;
                return this.guid == result.guid;
            }

            public String toString() {
                SerializedData data = new SerializedData();
                data.writeInt32(this.num);
                data.writeInt32(1);
                data.writeInt32(this.guid);
                return Utilities.bytesToHex(data.toByteArray());
            }

            /* JADX INFO: Access modifiers changed from: private */
            public void open() {
                this.openRunnable.run();
                if (this.rowName != null) {
                    final BaseFragment openingFragment = SettingsActivity.this.parentLayout.fragmentsStack.get(SettingsActivity.this.parentLayout.fragmentsStack.size() - 1);
                    try {
                        Field listViewField = openingFragment.getClass().getDeclaredField("listView");
                        listViewField.setAccessible(true);
                        RecyclerListView.IntReturnCallback callback = new RecyclerListView.IntReturnCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$SearchResult$b5nVtx-oa-MAypg8qdPXYKUfMDQ
                            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.IntReturnCallback
                            public final int run() {
                                return this.f$0.lambda$open$0$SettingsActivity$SearchAdapter$SearchResult(openingFragment);
                            }
                        };
                        RecyclerListView listView = (RecyclerListView) listViewField.get(openingFragment);
                        listView.highlightRow(callback);
                        listViewField.setAccessible(false);
                    } catch (Throwable th) {
                    }
                }
            }

            public /* synthetic */ int lambda$open$0$SettingsActivity$SearchAdapter$SearchResult(BaseFragment openingFragment) {
                int position = -1;
                try {
                    Field rowField = openingFragment.getClass().getDeclaredField(this.rowName);
                    Field linearLayoutField = openingFragment.getClass().getDeclaredField("layoutManager");
                    rowField.setAccessible(true);
                    linearLayoutField.setAccessible(true);
                    LinearLayoutManager layoutManager = (LinearLayoutManager) linearLayoutField.get(openingFragment);
                    position = rowField.getInt(openingFragment);
                    layoutManager.scrollToPositionWithOffset(position, 0);
                    rowField.setAccessible(false);
                    linearLayoutField.setAccessible(false);
                    return position;
                } catch (Throwable th) {
                    return position;
                }
            }
        }

        private class FaqSearchResult {
            private int num;
            private String[] path;
            private String title;
            private String url;

            public FaqSearchResult(String t, String[] p, String u) {
                this.title = t;
                this.path = p;
                this.url = u;
            }

            public boolean equals(Object obj) {
                if (!(obj instanceof FaqSearchResult)) {
                    return false;
                }
                FaqSearchResult result = (FaqSearchResult) obj;
                return this.title.equals(result.title);
            }

            public String toString() {
                SerializedData data = new SerializedData();
                data.writeInt32(this.num);
                data.writeInt32(0);
                data.writeString(this.title);
                String[] strArr = this.path;
                data.writeInt32(strArr != null ? strArr.length : 0);
                if (this.path != null) {
                    int a = 0;
                    while (true) {
                        String[] strArr2 = this.path;
                        if (a >= strArr2.length) {
                            break;
                        }
                        data.writeString(strArr2[a]);
                        a++;
                    }
                }
                data.writeString(this.url);
                return Utilities.bytesToHex(data.toByteArray());
            }
        }

        public /* synthetic */ void lambda$new$0$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ChangeNameActivity());
        }

        public /* synthetic */ void lambda$new$1$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ActionIntroActivity(3));
        }

        public /* synthetic */ void lambda$new$2$SettingsActivity$SearchAdapter() {
            int freeAccount = -1;
            int a = 0;
            while (true) {
                if (a >= 3) {
                    break;
                }
                if (UserConfig.getInstance(a).isClientActivated()) {
                    a++;
                } else {
                    freeAccount = a;
                    break;
                }
            }
            if (freeAccount >= 0) {
                SettingsActivity.this.presentFragment(new LoginActivity(freeAccount));
            }
        }

        public /* synthetic */ void lambda$new$3$SettingsActivity$SearchAdapter() {
            if (SettingsActivity.this.userInfo != null) {
                SettingsActivity.this.presentFragment(new ChangeBioActivity());
            }
        }

        public /* synthetic */ void lambda$new$4$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new NotificationsSettingsActivity());
        }

        public /* synthetic */ void lambda$new$5$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new NotificationsCustomSettingsActivity(1, new ArrayList(), true));
        }

        public /* synthetic */ void lambda$new$6$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new NotificationsCustomSettingsActivity(0, new ArrayList(), true));
        }

        public /* synthetic */ void lambda$new$7$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new NotificationsCustomSettingsActivity(2, new ArrayList(), true));
        }

        public /* synthetic */ void lambda$new$8$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new NotificationsSettingsActivity());
        }

        public /* synthetic */ void lambda$new$9$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new NotificationsSettingsActivity());
        }

        public /* synthetic */ void lambda$new$10$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new NotificationsSettingsActivity());
        }

        public /* synthetic */ void lambda$new$11$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new NotificationsSettingsActivity());
        }

        public /* synthetic */ void lambda$new$12$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new NotificationsSettingsActivity());
        }

        public /* synthetic */ void lambda$new$13$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new NotificationsSettingsActivity());
        }

        public /* synthetic */ void lambda$new$14$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacySettingsActivity());
        }

        public /* synthetic */ void lambda$new$15$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacyUsersActivity());
        }

        public /* synthetic */ void lambda$new$16$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacyControlActivity(6, true));
        }

        public /* synthetic */ void lambda$new$17$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacyControlActivity(0, true));
        }

        public /* synthetic */ void lambda$new$18$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacyControlActivity(4, true));
        }

        public /* synthetic */ void lambda$new$19$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacyControlActivity(5, true));
        }

        public /* synthetic */ void lambda$new$20$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacyControlActivity(3, true));
        }

        public /* synthetic */ void lambda$new$21$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacyControlActivity(2, true));
        }

        public /* synthetic */ void lambda$new$22$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacyControlActivity(1, true));
        }

        public /* synthetic */ void lambda$new$23$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PasscodeActivity(SharedConfig.passcodeHash.length() > 0 ? 2 : 0));
        }

        public /* synthetic */ void lambda$new$24$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new TwoStepVerificationActivity(0));
        }

        public /* synthetic */ void lambda$new$25$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new SessionsActivity(0));
        }

        public /* synthetic */ void lambda$new$26$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacySettingsActivity());
        }

        public /* synthetic */ void lambda$new$27$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacySettingsActivity());
        }

        public /* synthetic */ void lambda$new$28$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacySettingsActivity());
        }

        public /* synthetic */ void lambda$new$29$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new SessionsActivity(1));
        }

        public /* synthetic */ void lambda$new$30$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacySettingsActivity());
        }

        public /* synthetic */ void lambda$new$31$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacySettingsActivity());
        }

        public /* synthetic */ void lambda$new$32$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacySettingsActivity());
        }

        public /* synthetic */ void lambda$new$33$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacySettingsActivity());
        }

        public /* synthetic */ void lambda$new$34$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new PrivacySettingsActivity());
        }

        public /* synthetic */ void lambda$new$35$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$36$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$37$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new CacheControlActivity());
        }

        public /* synthetic */ void lambda$new$38$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new CacheControlActivity());
        }

        public /* synthetic */ void lambda$new$39$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new CacheControlActivity());
        }

        public /* synthetic */ void lambda$new$40$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new CacheControlActivity());
        }

        public /* synthetic */ void lambda$new$41$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataUsageActivity());
        }

        public /* synthetic */ void lambda$new$42$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$43$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataAutoDownloadActivity(0));
        }

        public /* synthetic */ void lambda$new$44$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataAutoDownloadActivity(1));
        }

        public /* synthetic */ void lambda$new$45$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataAutoDownloadActivity(2));
        }

        public /* synthetic */ void lambda$new$46$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$47$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$48$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$49$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$50$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$51$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$52$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$53$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$54$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new DataSettingsActivity());
        }

        public /* synthetic */ void lambda$new$55$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ProxyListActivity());
        }

        public /* synthetic */ void lambda$new$56$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ProxyListActivity());
        }

        public /* synthetic */ void lambda$new$57$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ThemeActivity(0));
        }

        public /* synthetic */ void lambda$new$58$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ThemeActivity(0));
        }

        public /* synthetic */ void lambda$new$59$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new WallpapersListActivity(0));
        }

        public /* synthetic */ void lambda$new$60$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new WallpapersListActivity(1));
        }

        public /* synthetic */ void lambda$new$61$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new WallpapersListActivity(0));
        }

        public /* synthetic */ void lambda$new$62$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ThemeActivity(1));
        }

        public /* synthetic */ void lambda$new$63$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ThemeActivity(0));
        }

        public /* synthetic */ void lambda$new$64$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ThemeActivity(0));
        }

        public /* synthetic */ void lambda$new$65$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ThemeActivity(0));
        }

        public /* synthetic */ void lambda$new$66$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ThemeActivity(0));
        }

        public /* synthetic */ void lambda$new$67$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ThemeActivity(0));
        }

        public /* synthetic */ void lambda$new$68$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ThemeActivity(0));
        }

        public /* synthetic */ void lambda$new$69$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ThemeActivity(0));
        }

        public /* synthetic */ void lambda$new$70$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ThemeActivity(0));
        }

        public /* synthetic */ void lambda$new$71$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new StickersActivity(0));
        }

        public /* synthetic */ void lambda$new$72$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new StickersActivity(0));
        }

        public /* synthetic */ void lambda$new$73$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new FeaturedStickersActivity());
        }

        public /* synthetic */ void lambda$new$74$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new StickersActivity(1));
        }

        public /* synthetic */ void lambda$new$75$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ArchivedStickersActivity(0));
        }

        public /* synthetic */ void lambda$new$76$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new ArchivedStickersActivity(1));
        }

        public /* synthetic */ void lambda$new$77$SettingsActivity$SearchAdapter() {
            SettingsActivity.this.presentFragment(new LanguageSelectActivity());
        }

        public /* synthetic */ void lambda$new$79$SettingsActivity$SearchAdapter() {
            SettingsActivity settingsActivity = SettingsActivity.this;
            settingsActivity.showDialog(AlertsCreator.createSupportAlert(settingsActivity));
        }

        public /* synthetic */ void lambda$new$80$SettingsActivity$SearchAdapter() {
            Browser.openUrl(SettingsActivity.this.getParentActivity(), LocaleController.getString("AppFaqUrl", R.string.AppFaqUrl));
        }

        public /* synthetic */ void lambda$new$81$SettingsActivity$SearchAdapter() {
            Browser.openUrl(SettingsActivity.this.getParentActivity(), LocaleController.getString("PrivacyPolicyUrl", R.string.PrivacyPolicyUrl));
        }

        public SearchAdapter(Context context) {
            String string = LocaleController.getString("SettingsHelp", R.string.SettingsHelp);
            final SettingsActivity settingsActivity = SettingsActivity.this;
            this.searchArray = new SearchResult[]{new SearchResult(this, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION, LocaleController.getString("EditName", R.string.EditName), 0, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$gb5TdQl-FuVGKPdZhJ5Q6f9r2NE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$0$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 501, LocaleController.getString("ChangePhoneNumber", R.string.ChangePhoneNumber), 0, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$3CvN_NN_qDqhV15-E1lAMYiU6bA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$1$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 502, LocaleController.getString("AddAnotherAccount", R.string.AddAnotherAccount), 0, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$QG1sACBV0qdDaE1nnfpI9rZbpTM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$2$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 503, LocaleController.getString("UserBio", R.string.UserBio), 0, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$mSS4jMLwxUVqwDHHhhSWMcqE9lI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$3$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 1, LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.menu_notifications, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$oRVCn4DEKliD2d3WB3Enzj-91Vo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$4$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 2, LocaleController.getString("NotificationsPrivateChats", R.string.NotificationsPrivateChats), LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.menu_notifications, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$lkNQ094frOl0RD5QHBKyiRXJhoI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$5$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 3, LocaleController.getString("NotificationsGroups", R.string.NotificationsGroups), LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.menu_notifications, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$8NcnHB8uAkAetU1BQRpwGpKYvZo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$6$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 4, LocaleController.getString("NotificationsChannels", R.string.NotificationsChannels), LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.menu_notifications, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$byCyHG_2LJv1VBYek-pAv7obXLg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$7$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 5, LocaleController.getString("VoipNotificationSettings", R.string.VoipNotificationSettings), "callsSectionRow", LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.menu_notifications, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$XbeiGvZprm2qyqqEt2QBhEUuhtg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$8$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 6, LocaleController.getString("BadgeNumber", R.string.BadgeNumber), "badgeNumberSection", LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.menu_notifications, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$20cXj8HPGGMwzfbeXlEELmnpqaI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$9$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 7, LocaleController.getString("InAppNotifications", R.string.InAppNotifications), "inappSectionRow", LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.menu_notifications, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$qybLLycKmL_KMuFz3wiqA51cU0A
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$10$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 8, LocaleController.getString("ContactJoined", R.string.ContactJoined), "contactJoinedRow", LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.menu_notifications, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$T37TSqJbWsrZvRMjR2Snj45F0OE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$11$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 9, LocaleController.getString("PinnedMessages", R.string.PinnedMessages), "pinnedMessageRow", LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.menu_notifications, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$QrdbWRNNsc-r_6otQPfsE3bNXko
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$12$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 10, LocaleController.getString("ResetAllNotifications", R.string.ResetAllNotifications), "resetNotificationsRow", LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.menu_notifications, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$wBQmtt-yNImjGD_kEqbFPj8Mkb0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$13$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 100, LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$G1B5zMSwMF8RwLxrvIjG6E2AYY4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$14$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 101, LocaleController.getString("BlockedUsers", R.string.BlockedUsers), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$qA5XcROYW4F5iV1SG8Uc3qmpvhs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$15$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 105, LocaleController.getString("PrivacyPhone", R.string.PrivacyPhone), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$-irJhXVU3vDBwvAA7g4wmQ-UtcU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$16$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 102, LocaleController.getString("PrivacyLastSeen", R.string.PrivacyLastSeen), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$M4uIuM2V4bWuZ7J5oMyoB1fZEbM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$17$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 103, LocaleController.getString("PrivacyProfilePhoto", R.string.PrivacyProfilePhoto), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$I_l32Msvc1esb-7hpIISJhYAy4c
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$18$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 104, LocaleController.getString("PrivacyForwards", R.string.PrivacyForwards), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$qO8xM9c_uITs4b-vkWiSeP7UJno
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$19$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 105, LocaleController.getString("PrivacyP2P", R.string.PrivacyP2P), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$P6vF8W_uFGuvIs35oZ2GYYUwHdM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$20$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 106, LocaleController.getString("Calls", R.string.Calls), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$Ixi1k639IYlvEaCKZYwoNIamhbI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$21$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 107, LocaleController.getString("GroupsAndChannels", R.string.GroupsAndChannels), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$psZLvwVciiZHFZMc7ZrmmRh9N7g
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$22$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 108, LocaleController.getString("Passcode", R.string.Passcode), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$fKXRjKYfJ6ejuovOwavzGZ0alT0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$23$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 109, LocaleController.getString("TwoStepVerification", R.string.TwoStepVerification), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$nkRJx-z8hvJ_Pv5qKpWT5qIsz-o
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$24$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 110, LocaleController.getString("SessionsTitle", R.string.SessionsTitle), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$_V0LmRrVmcD1hWV6lUpvAuNuyfI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$25$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 111, LocaleController.getString("PrivacyDeleteCloudDrafts", R.string.PrivacyDeleteCloudDrafts), "clearDraftsRow", LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$MHfnWxrc8Mphu7NqxT67TQIO1tw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$26$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 112, LocaleController.getString("DeleteAccountIfAwayFor2", R.string.DeleteAccountIfAwayFor2), "deleteAccountRow", LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$Gys_ooX22YiO0AA0ZRPv9t2nYGE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$27$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 113, LocaleController.getString("PrivacyPaymentsClear", R.string.PrivacyPaymentsClear), "paymentsClearRow", LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$IoIfp6LC5Xovmk1tcuUK4b42Jyk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$28$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 114, LocaleController.getString("WebSessionsTitle", R.string.WebSessionsTitle), LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$tkne2Rh9ZSH61DzM3480H9XlqeQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$29$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 115, LocaleController.getString("SyncContactsDelete", R.string.SyncContactsDelete), "contactsDeleteRow", LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$VlikkTChj4o1O2c7iZ46C41TlQc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$30$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 116, LocaleController.getString("SyncContacts", R.string.SyncContacts), "contactsSyncRow", LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$SjdwuUgJRbC184znjR5dLcjDubc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$31$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 117, LocaleController.getString("SuggestContacts", R.string.SuggestContacts), "contactsSuggestRow", LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$jcRmrFeYrVG6fY4WrFxvwLafZUw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$32$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 118, LocaleController.getString("MapPreviewProvider", R.string.MapPreviewProvider), "secretMapRow", LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$RBEx_btxua8mN9A03GZhJcCsVXA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$33$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 119, LocaleController.getString("SecretWebPage", R.string.SecretWebPage), "secretWebpageRow", LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$YFyyAAcIV2JXSOk8lu7ydzvP0uc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$34$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$mhR1h0o1rDdECcFZ7aEWjRxvq7I
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$35$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 201, LocaleController.getString("DataUsage", R.string.DataUsage), "usageSectionRow", LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$AouSDlfrfQmLCrbCkjLZD1C3sEc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$36$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 202, LocaleController.getString("StorageUsage", R.string.StorageUsage), LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$SqGl8nuvEeT67FTYMMgYzjpxjIE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$37$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(203, LocaleController.getString("KeepMedia", R.string.KeepMedia), "keepMediaRow", LocaleController.getString("DataSettings", R.string.DataSettings), LocaleController.getString("StorageUsage", R.string.StorageUsage), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$NEmkqQtJRNxzrT1pyZUrISNM9xI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$38$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(204, LocaleController.getString("ClearMediaCache", R.string.ClearMediaCache), "cacheRow", LocaleController.getString("DataSettings", R.string.DataSettings), LocaleController.getString("StorageUsage", R.string.StorageUsage), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$bkPHTOg_1atqE9ZIjxz3SF0r7Jc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$39$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(205, LocaleController.getString("LocalDatabase", R.string.LocalDatabase), "databaseRow", LocaleController.getString("DataSettings", R.string.DataSettings), LocaleController.getString("StorageUsage", R.string.StorageUsage), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$8l_yJnl7VK3DmbWtlsWW92FcVhc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$40$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 206, LocaleController.getString("NetworkUsage", R.string.NetworkUsage), LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$UhV1wSVIuGtbOeX0iUJB9k2qmmk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$41$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, MessageObject.TYPE_LIVE, LocaleController.getString("AutomaticMediaDownload", R.string.AutomaticMediaDownload), "mediaDownloadSectionRow", LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$B4qXUSWlnoDpDEmJgMbSNpi7DEQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$42$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 208, LocaleController.getString("WhenUsingMobileData", R.string.WhenUsingMobileData), LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$_F-kpuII8HQ6LkI_QYl-4VhTEbk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$43$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 209, LocaleController.getString("WhenConnectedOnWiFi", R.string.WhenConnectedOnWiFi), LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$2CJWigW11zbT1PYMuI08F4Oa83o
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$44$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 210, LocaleController.getString("WhenRoaming", R.string.WhenRoaming), LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$gq_4QCdpw_34-rC0wDS4QC7pjcM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$45$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 211, LocaleController.getString("ResetAutomaticMediaDownload", R.string.ResetAutomaticMediaDownload), "resetDownloadRow", LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$TOQod9eBYCyaCUWBzAmZ082ZQq4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$46$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 212, LocaleController.getString("AutoplayMedia", R.string.AutoplayMedia), "autoplayHeaderRow", LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$5qsO2JpOMT_rifeDQ_6QYV-ej98
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$47$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 213, LocaleController.getString("AutoplayGIF", R.string.AutoplayGIF), "autoplayGifsRow", LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$N6warWKC-QBSIyQV5XTjBXN8XRo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$48$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 214, LocaleController.getString("AutoplayVideo", R.string.AutoplayVideo), "autoplayVideoRow", LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$dkBAJZadXOHvE-By00bdjKoqU3g
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$49$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 215, LocaleController.getString("Streaming", R.string.Streaming), "streamSectionRow", LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$tmk5KAhZBAOcIKNk6r1DlSsjkYo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$50$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 216, LocaleController.getString("EnableStreaming", R.string.EnableStreaming), "enableStreamRow", LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$F0p1QFO2cdqAHMaUdRrgS_pb-7o
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$51$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 217, LocaleController.getString("Calls", R.string.Calls), "callsSectionRow", LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$HQ7meEtz3krQJx8e7iEMHGT_a-4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$52$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 218, LocaleController.getString("VoipUseLessData", R.string.VoipUseLessData), "useLessDataForCallsRow", LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$QLdSuQ3MuCIdCR9Slpup6cJSGtI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$53$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 219, LocaleController.getString("VoipQuickReplies", R.string.VoipQuickReplies), "quickRepliesRow", LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$2lLS5sQ_sb6En_C3y2cCjLwQp9I
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$54$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 220, LocaleController.getString("ProxySettings", R.string.ProxySettings), LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$z4JuMBevGQzA--UXdfNG8UHdglQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$55$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(221, LocaleController.getString("UseProxyForCalls", R.string.UseProxyForCalls), "callsRow", LocaleController.getString("DataSettings", R.string.DataSettings), LocaleController.getString("ProxySettings", R.string.ProxySettings), R.drawable.menu_data, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$GbMex6YgNEV6YuYVE0E2cCAe-Wc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$56$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 300, LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$xay4D0DgSJPoRpOgjR6sjFirrlY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$57$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 301, LocaleController.getString("TextSizeHeader", R.string.TextSizeHeader), "textSizeHeaderRow", LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$392jyg7mFNXhUX-y_Zz0E8owqbE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$58$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 302, LocaleController.getString("ChatBackground", R.string.ChatBackground), LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$sRDVYFbq7Td1ISNMn56G8da_Muw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$59$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(303, LocaleController.getString("SetColor", R.string.SetColor), null, LocaleController.getString("ChatSettings", R.string.ChatSettings), LocaleController.getString("ChatBackground", R.string.ChatBackground), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$ALS-ZEcRTQqgvsM9VCcM5KlUEtI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$60$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(304, LocaleController.getString("ResetChatBackgrounds", R.string.ResetChatBackgrounds), "resetRow", LocaleController.getString("ChatSettings", R.string.ChatSettings), LocaleController.getString("ChatBackground", R.string.ChatBackground), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$656P3kaScrBaGtwNKdoBvag0YYM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$61$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 305, LocaleController.getString("AutoNightTheme", R.string.AutoNightTheme), LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$EHbtS22EE3SmzxsTV3D3ahhD_6g
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$62$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 306, LocaleController.getString("ColorTheme", R.string.ColorTheme), "themeHeaderRow", LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$dXL4ZDbGg_VHuX3WY2ztv9-kVEk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$63$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, StatusLine.HTTP_TEMP_REDIRECT, LocaleController.getString("ChromeCustomTabs", R.string.ChromeCustomTabs), "customTabsRow", LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$2BLEmM9ahCvHRWt3Vb9rBtf5LPc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$64$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, StatusLine.HTTP_PERM_REDIRECT, LocaleController.getString("DirectShare", R.string.DirectShare), "directShareRow", LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$bYL_6hpYbOrUOSSffqWtRJbHd_E
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$65$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 309, LocaleController.getString("EnableAnimations", R.string.EnableAnimations), "enableAnimationsRow", LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$eYw_RzdV5lmVOZKishluTalUdD8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$66$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 310, LocaleController.getString("RaiseToSpeak", R.string.RaiseToSpeak), "raiseToSpeakRow", LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$KUeMqgRstLY18Gd-SsCVeRk-8Uw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$67$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 311, LocaleController.getString("SendByEnter", R.string.SendByEnter), "sendByEnterRow", LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$fjoeCwakj2hpnl6tqY-xdX8Jg0Q
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$68$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 312, LocaleController.getString("SaveToGallerySettings", R.string.SaveToGallerySettings), "saveToGalleryRow", LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$wWyxEv_Ah_Pad_WBTgxSmTbwnqE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$69$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 312, LocaleController.getString("DistanceUnits", R.string.DistanceUnits), "distanceRow", LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$hW6k8vlPJfWcAp6sGRL2rLy39So
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$70$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 313, LocaleController.getString("StickersAndMasks", R.string.StickersAndMasks), LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$bgQ_ole_HV_V2BTdq6RLlRslZ_o
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$71$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(314, LocaleController.getString("SuggestStickers", R.string.SuggestStickers), "suggestRow", LocaleController.getString("ChatSettings", R.string.ChatSettings), LocaleController.getString("StickersAndMasks", R.string.StickersAndMasks), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$7pwi33uV6rQc9hkVsu6UlvtVQt8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$72$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(315, LocaleController.getString("FeaturedStickers", R.string.FeaturedStickers), null, LocaleController.getString("ChatSettings", R.string.ChatSettings), LocaleController.getString("StickersAndMasks", R.string.StickersAndMasks), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$CdMWl7Ic5N4_2G_5phnBWErb0i8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$73$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(316, LocaleController.getString("Masks", R.string.Masks), null, LocaleController.getString("ChatSettings", R.string.ChatSettings), LocaleController.getString("StickersAndMasks", R.string.StickersAndMasks), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$cjndjRhdiDDDxRyy1u-c6tlbu1o
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$74$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(317, LocaleController.getString("ArchivedStickers", R.string.ArchivedStickers), null, LocaleController.getString("ChatSettings", R.string.ChatSettings), LocaleController.getString("StickersAndMasks", R.string.StickersAndMasks), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$cn5quMRbEIMpUrVsUC5g9HZpFVk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$75$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(317, LocaleController.getString("ArchivedMasks", R.string.ArchivedMasks), null, LocaleController.getString("ChatSettings", R.string.ChatSettings), LocaleController.getString("StickersAndMasks", R.string.StickersAndMasks), R.drawable.menu_chats, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$fyFTMWpIPsMNIi6L6M7TatAkPFY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$76$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 400, LocaleController.getString("Language", R.string.Language), R.drawable.menu_language, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$X71JnTb8ojKU2r9XZhR_9r8k0tk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$77$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 401, string, R.drawable.menu_help, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$tKME9hgrn4yC_uG2Ll1hyQ_uBac
                @Override // java.lang.Runnable
                public final void run() {
                    settingsActivity.showHelpAlert();
                }
            }), new SearchResult(this, 402, LocaleController.getString("AskAQuestion", R.string.AskAQuestion), LocaleController.getString("SettingsHelp", R.string.SettingsHelp), R.drawable.menu_help, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$2DaspYNGIbhGTxCpp1Xk6Ru7hcc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$79$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 403, LocaleController.getString("AppFaq", R.string.AppFaq), LocaleController.getString("SettingsHelp", R.string.SettingsHelp), R.drawable.menu_help, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$79kPM-D_h_dp7RiLyyTbO2vSP-U
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$80$SettingsActivity$SearchAdapter();
                }
            }), new SearchResult(this, 404, LocaleController.getString("PrivacyPolicy", R.string.PrivacyPolicy), LocaleController.getString("SettingsHelp", R.string.SettingsHelp), R.drawable.menu_help, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$cKAwr7WCrg_G4uyI88C2BN9cn4k
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$81$SettingsActivity$SearchAdapter();
                }
            })};
            this.faqSearchArray = new ArrayList<>();
            this.resultNames = new ArrayList<>();
            this.searchResults = new ArrayList<>();
            this.faqSearchResults = new ArrayList<>();
            this.recentSearches = new ArrayList<>();
            this.mContext = context;
            HashMap<Integer, SearchResult> resultHashMap = new HashMap<>();
            int a = 0;
            while (true) {
                SearchResult[] searchResultArr = this.searchArray;
                if (a >= searchResultArr.length) {
                    break;
                }
                resultHashMap.put(Integer.valueOf(searchResultArr[a].guid), this.searchArray[a]);
                a++;
            }
            Set<String> set = MessagesController.getGlobalMainSettings().getStringSet("settingsSearchRecent2", null);
            if (set != null) {
                for (String value : set) {
                    try {
                        SerializedData data = new SerializedData(Utilities.hexToBytes(value));
                        int num = data.readInt32(false);
                        int type = data.readInt32(false);
                        if (type == 0) {
                            String title = data.readString(false);
                            int count = data.readInt32(false);
                            String[] path = null;
                            if (count > 0) {
                                path = new String[count];
                                for (int a2 = 0; a2 < count; a2++) {
                                    path[a2] = data.readString(false);
                                }
                            }
                            String url = data.readString(false);
                            FaqSearchResult result = new FaqSearchResult(title, path, url);
                            result.num = num;
                            this.recentSearches.add(result);
                        } else if (type == 1) {
                            try {
                                SearchResult result2 = resultHashMap.get(Integer.valueOf(data.readInt32(false)));
                                if (result2 != null) {
                                    result2.num = num;
                                    this.recentSearches.add(result2);
                                }
                            } catch (Exception e) {
                            }
                        }
                    } catch (Exception e2) {
                    }
                }
            }
            Collections.sort(this.recentSearches, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$Qtio3ZO10H3xvQt5NrcdGNOchPo
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return this.f$0.lambda$new$82$SettingsActivity$SearchAdapter(obj, obj2);
                }
            });
        }

        public /* synthetic */ int lambda$new$82$SettingsActivity$SearchAdapter(Object o1, Object o2) {
            int n1 = getNum(o1);
            int n2 = getNum(o2);
            if (n1 < n2) {
                return -1;
            }
            if (n1 > n2) {
                return 1;
            }
            return 0;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void loadFaqWebPage() {
            if (this.faqWebPage != null || this.loadingFaqPage) {
                return;
            }
            this.loadingFaqPage = true;
            TLRPC.TL_messages_getWebPage req2 = new TLRPC.TL_messages_getWebPage();
            req2.url = LocaleController.getString("AppFaqUrl", R.string.AppFaqUrl);
            req2.hash = 0;
            ConnectionsManager.getInstance(SettingsActivity.this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$IUPZMBV_9CLSwJ02RvobEMU393Q
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadFaqWebPage$83$SettingsActivity$SearchAdapter(tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$loadFaqWebPage$83$SettingsActivity$SearchAdapter(TLObject response2, TLRPC.TL_error error2) {
            if (response2 instanceof TLRPC.WebPage) {
                TLRPC.WebPage page = (TLRPC.WebPage) response2;
                if (page.cached_page != null) {
                    int N = page.cached_page.blocks.size();
                    for (int a = 0; a < N; a++) {
                        TLRPC.PageBlock block = page.cached_page.blocks.get(a);
                        if (block instanceof TLRPC.TL_pageBlockList) {
                            String paragraph = null;
                            if (a != 0) {
                                TLRPC.PageBlock prevBlock = page.cached_page.blocks.get(a - 1);
                                if (prevBlock instanceof TLRPC.TL_pageBlockParagraph) {
                                    TLRPC.TL_pageBlockParagraph pageBlockParagraph = (TLRPC.TL_pageBlockParagraph) prevBlock;
                                    paragraph = ArticleViewer.getPlainText(pageBlockParagraph.text).toString();
                                }
                            }
                            TLRPC.TL_pageBlockList list = (TLRPC.TL_pageBlockList) block;
                            int N2 = list.items.size();
                            for (int b = 0; b < N2; b++) {
                                TLRPC.PageListItem item = list.items.get(b);
                                if (item instanceof TLRPC.TL_pageListItemText) {
                                    TLRPC.TL_pageListItemText itemText = (TLRPC.TL_pageListItemText) item;
                                    String url = ArticleViewer.getUrl(itemText.text);
                                    String text = ArticleViewer.getPlainText(itemText.text).toString();
                                    if (!TextUtils.isEmpty(url) && !TextUtils.isEmpty(text)) {
                                        String[] path = paragraph != null ? new String[]{LocaleController.getString("SettingsSearchFaq", R.string.SettingsSearchFaq), paragraph} : new String[]{LocaleController.getString("SettingsSearchFaq", R.string.SettingsSearchFaq)};
                                        this.faqSearchArray.add(new FaqSearchResult(text, path, url));
                                    }
                                }
                            }
                        } else if (block instanceof TLRPC.TL_pageBlockAnchor) {
                            break;
                        }
                    }
                    this.faqWebPage = page;
                }
            }
            this.loadingFaqPage = false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (this.searchWas) {
                return this.searchResults.size() + (this.faqSearchResults.isEmpty() ? 0 : this.faqSearchResults.size() + 1);
            }
            if (this.recentSearches.isEmpty()) {
                return 0;
            }
            return this.recentSearches.size() + 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() == 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int icon;
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 1) {
                    GraySectionCell sectionCell = (GraySectionCell) holder.itemView;
                    sectionCell.setText(LocaleController.getString("SettingsFaqSearchTitle", R.string.SettingsFaqSearchTitle));
                    return;
                } else {
                    if (itemViewType == 2) {
                        HeaderCell headerCell = (HeaderCell) holder.itemView;
                        headerCell.setText(LocaleController.getString("SettingsRecent", R.string.SettingsRecent));
                        return;
                    }
                    return;
                }
            }
            SettingsSearchCell searchCell = (SettingsSearchCell) holder.itemView;
            if (this.searchWas) {
                if (position < this.searchResults.size()) {
                    SearchResult result = this.searchResults.get(position);
                    SearchResult prevResult = position > 0 ? this.searchResults.get(position - 1) : null;
                    if (prevResult == null || prevResult.iconResId != result.iconResId) {
                        icon = result.iconResId;
                    } else {
                        icon = 0;
                    }
                    searchCell.setTextAndValueAndIcon(this.resultNames.get(position), result.path, icon, position < this.searchResults.size() - 1);
                    return;
                }
                int position2 = position - (this.searchResults.size() + 1);
                searchCell.setTextAndValue(this.resultNames.get(this.searchResults.size() + position2), this.faqSearchResults.get(position2).path, true, position2 < this.searchResults.size() - 1);
                return;
            }
            int position3 = position - 1;
            Object object = this.recentSearches.get(position3);
            if (object instanceof SearchResult) {
                SearchResult result2 = (SearchResult) object;
                searchCell.setTextAndValue(result2.searchTitle, result2.path, false, position3 < this.recentSearches.size() - 1);
            } else if (object instanceof FaqSearchResult) {
                FaqSearchResult result3 = (FaqSearchResult) object;
                searchCell.setTextAndValue(result3.title, result3.path, true, position3 < this.recentSearches.size() - 1);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new SettingsSearchCell(this.mContext);
            } else if (viewType == 1) {
                view = new GraySectionCell(this.mContext);
            } else {
                view = new HeaderCell(this.mContext, 16);
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return this.searchWas ? (position >= this.searchResults.size() && position == this.searchResults.size()) ? 1 : 0 : position == 0 ? 2 : 0;
        }

        public void addRecent(Object object) {
            int index = this.recentSearches.indexOf(object);
            if (index >= 0) {
                this.recentSearches.remove(index);
            }
            this.recentSearches.add(0, object);
            if (!this.searchWas) {
                notifyDataSetChanged();
            }
            if (this.recentSearches.size() > 20) {
                this.recentSearches.remove(r1.size() - 1);
            }
            LinkedHashSet<String> toSave = new LinkedHashSet<>();
            int N = this.recentSearches.size();
            for (int a = 0; a < N; a++) {
                Object o = this.recentSearches.get(a);
                if (o instanceof SearchResult) {
                    ((SearchResult) o).num = a;
                } else if (o instanceof FaqSearchResult) {
                    ((FaqSearchResult) o).num = a;
                }
                toSave.add(o.toString());
            }
            MessagesController.getGlobalMainSettings().edit().putStringSet("settingsSearchRecent2", toSave).commit();
        }

        public void clearRecent() {
            this.recentSearches.clear();
            MessagesController.getGlobalMainSettings().edit().remove("settingsSearchRecent2").commit();
            notifyDataSetChanged();
        }

        private int getNum(Object o) {
            if (o instanceof SearchResult) {
                return ((SearchResult) o).num;
            }
            if (o instanceof FaqSearchResult) {
                return ((FaqSearchResult) o).num;
            }
            return 0;
        }

        public void search(final String text) {
            this.lastSearchString = text;
            if (this.searchRunnable != null) {
                Utilities.searchQueue.cancelRunnable(this.searchRunnable);
                this.searchRunnable = null;
            }
            if (TextUtils.isEmpty(text)) {
                this.searchWas = false;
                this.searchResults.clear();
                this.faqSearchResults.clear();
                this.resultNames.clear();
                SettingsActivity.this.emptyView.setTopImage(0);
                SettingsActivity.this.emptyView.setText(LocaleController.getString("SettingsNoRecent", R.string.SettingsNoRecent));
                notifyDataSetChanged();
                return;
            }
            DispatchQueue dispatchQueue = Utilities.searchQueue;
            Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SettingsActivity$SearchAdapter$6AZa8R4bx8rJeZDGcU_Y01EpMFI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$search$85$SettingsActivity$SearchAdapter(text);
                }
            };
            this.searchRunnable = runnable;
            dispatchQueue.postRunnable(runnable, 300L);
        }

        /* JADX WARN: Removed duplicated region for block: B:44:0x00fa  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public /* synthetic */ void lambda$search$85$SettingsActivity$SearchAdapter(final java.lang.String r20) {
            /*
                Method dump skipped, instruction units count: 496
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.SettingsActivity.SearchAdapter.lambda$search$85$SettingsActivity$SearchAdapter(java.lang.String):void");
        }

        public /* synthetic */ void lambda$null$84$SettingsActivity$SearchAdapter(String text, ArrayList results, ArrayList faqResults, ArrayList names) {
            if (!text.equals(this.lastSearchString)) {
                return;
            }
            if (!this.searchWas) {
                SettingsActivity.this.emptyView.setTopImage(R.drawable.settings_noresults);
                SettingsActivity.this.emptyView.setText(LocaleController.getString("SettingsNoResults", R.string.SettingsNoResults));
            }
            this.searchWas = true;
            this.searchResults = results;
            this.faqSearchResults = faqResults;
            this.resultNames = names;
            notifyDataSetChanged();
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return SettingsActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String value;
            String value2;
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                if (position == SettingsActivity.this.overscrollRow) {
                    ((EmptyCell) holder.itemView).setHeight(AndroidUtilities.dp(88.0f));
                    return;
                }
                return;
            }
            if (itemViewType == 2) {
                TextCell textCell = (TextCell) holder.itemView;
                if (position != SettingsActivity.this.languageRow) {
                    if (position != SettingsActivity.this.notificationRow) {
                        if (position != SettingsActivity.this.privacyRow) {
                            if (position != SettingsActivity.this.dataRow) {
                                if (position != SettingsActivity.this.chatRow) {
                                    if (position == SettingsActivity.this.helpRow) {
                                        textCell.setTextAndIcon(LocaleController.getString("SettingsHelp", R.string.SettingsHelp), R.drawable.menu_help, false);
                                        return;
                                    }
                                    return;
                                }
                                textCell.setTextAndIcon(LocaleController.getString("ChatSettings", R.string.ChatSettings), R.drawable.menu_chats, true);
                                return;
                            }
                            textCell.setTextAndIcon(LocaleController.getString("DataSettings", R.string.DataSettings), R.drawable.menu_data, true);
                            return;
                        }
                        textCell.setTextAndIcon(LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.menu_secret, true);
                        return;
                    }
                    textCell.setTextAndIcon(LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.menu_notifications, true);
                    return;
                }
                textCell.setTextAndIcon(LocaleController.getString("Language", R.string.Language), R.drawable.menu_language, true);
                return;
            }
            if (itemViewType == 4) {
                if (position != SettingsActivity.this.settingsSectionRow2) {
                    if (position == SettingsActivity.this.numberSectionRow) {
                        ((HeaderCell) holder.itemView).setText(LocaleController.getString("Account", R.string.Account));
                        return;
                    }
                    return;
                }
                ((HeaderCell) holder.itemView).setText(LocaleController.getString("SETTINGS", R.string.SETTINGS));
                return;
            }
            if (itemViewType == 6) {
                TextDetailCell textCell2 = (TextDetailCell) holder.itemView;
                if (position == SettingsActivity.this.numberRow) {
                    TLRPC.User user = UserConfig.getInstance(SettingsActivity.this.currentAccount).getCurrentUser();
                    if (user != null && user.phone != null && user.phone.length() != 0) {
                        value2 = PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + user.phone);
                    } else {
                        value2 = LocaleController.getString("NumberUnknown", R.string.NumberUnknown);
                    }
                    textCell2.setTextAndValue(value2, LocaleController.getString("TapToChangePhone", R.string.TapToChangePhone), true);
                    return;
                }
                if (position == SettingsActivity.this.usernameRow) {
                    TLRPC.User user2 = UserConfig.getInstance(SettingsActivity.this.currentAccount).getCurrentUser();
                    if (user2 != null && !TextUtils.isEmpty(user2.username)) {
                        value = "@" + user2.username;
                    } else {
                        value = LocaleController.getString("UsernameEmpty", R.string.UsernameEmpty);
                    }
                    textCell2.setTextAndValue(value, LocaleController.getString("Username", R.string.Username), true);
                    return;
                }
                if (position == SettingsActivity.this.bioRow) {
                    if (SettingsActivity.this.userInfo == null || !TextUtils.isEmpty(SettingsActivity.this.userInfo.about)) {
                        String value3 = SettingsActivity.this.userInfo == null ? LocaleController.getString("Loading", R.string.Loading) : SettingsActivity.this.userInfo.about;
                        textCell2.setTextWithEmojiAndValue(value3, LocaleController.getString("UserBio", R.string.UserBio), false);
                    } else {
                        textCell2.setTextAndValue(LocaleController.getString("UserBio", R.string.UserBio), LocaleController.getString("UserBioDetail", R.string.UserBioDetail), false);
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == SettingsActivity.this.notificationRow || position == SettingsActivity.this.numberRow || position == SettingsActivity.this.privacyRow || position == SettingsActivity.this.languageRow || position == SettingsActivity.this.usernameRow || position == SettingsActivity.this.bioRow || position == SettingsActivity.this.versionRow || position == SettingsActivity.this.dataRow || position == SettingsActivity.this.chatRow || position == SettingsActivity.this.helpRow;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new EmptyCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 1) {
                view = new ShadowSectionCell(this.mContext);
            } else if (viewType == 2) {
                view = new TextCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 4) {
                view = new HeaderCell(this.mContext, 23);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 5) {
                TextInfoPrivacyCell cell = new TextInfoPrivacyCell(this.mContext, 10);
                cell.getTextView().setGravity(1);
                cell.getTextView().setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
                cell.getTextView().setMovementMethod(null);
                cell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                try {
                    PackageInfo pInfo = ApplicationLoader.applicationContext.getPackageManager().getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0);
                    int code = pInfo.versionCode / 10;
                    String abi = "";
                    switch (pInfo.versionCode % 10) {
                        case 0:
                        case 9:
                            abi = "universal " + Build.CPU_ABI + " " + Build.CPU_ABI2;
                            break;
                        case 1:
                        case 3:
                            abi = "arm-v7a";
                            break;
                        case 2:
                        case 4:
                            abi = "x86";
                            break;
                        case 5:
                        case 7:
                            abi = "arm64-v8a";
                            break;
                        case 6:
                        case 8:
                            abi = "x86_64";
                            break;
                    }
                    cell.setText(LocaleController.formatString("AppVersion", R.string.AppVersion, String.format(Locale.US, "v%s (%d) %s", pInfo.versionName, Integer.valueOf(code), abi)));
                } catch (Exception e) {
                    FileLog.e(e);
                }
                cell.getTextView().setPadding(0, AndroidUtilities.dp(14.0f), 0, AndroidUtilities.dp(14.0f));
                view = cell;
            } else if (viewType == 6) {
                view = new TextDetailCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != SettingsActivity.this.overscrollRow) {
                if (position != SettingsActivity.this.settingsSectionRow) {
                    if (position == SettingsActivity.this.notificationRow || position == SettingsActivity.this.privacyRow || position == SettingsActivity.this.languageRow || position == SettingsActivity.this.dataRow || position == SettingsActivity.this.chatRow || position == SettingsActivity.this.helpRow) {
                        return 2;
                    }
                    if (position != SettingsActivity.this.versionRow) {
                        if (position == SettingsActivity.this.numberRow || position == SettingsActivity.this.usernameRow || position == SettingsActivity.this.bioRow) {
                            return 6;
                        }
                        return (position == SettingsActivity.this.settingsSectionRow2 || position == SettingsActivity.this.numberSectionRow) ? 4 : 2;
                    }
                    return 5;
                }
                return 1;
            }
            return 0;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{EmptyCell.class, HeaderCell.class, TextDetailCell.class, TextCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND | ThemeDescription.FLAG_CHECKTAG, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND | ThemeDescription.FLAG_CHECKTAG, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_avatar_backgroundActionBarBlue), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_avatar_backgroundActionBarBlue), new ThemeDescription(this.extraHeightView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_avatar_backgroundActionBarBlue), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_avatar_actionBarIconBlue), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_avatar_actionBarSelectorBlue), new ThemeDescription(this.nameTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_profile_title), new ThemeDescription(this.onlineTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_profile_status), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUBACKGROUND, null, null, null, null, Theme.key_actionBarDefaultSubmenuBackground), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM, null, null, null, null, Theme.key_actionBarDefaultSubmenuItem), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM | ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_actionBarDefaultSubmenuItemIcon), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, 0, new Class[]{TextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, 0, new Class[]{TextDetailCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextDetailCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.avatarImage, 0, null, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(this.avatarImage, 0, null, null, new Drawable[]{this.avatarDrawable}, null, Theme.key_avatar_backgroundInProfileBlue), new ThemeDescription(this.writeButton, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_profile_actionIcon), new ThemeDescription(this.writeButton, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_profile_actionBackground), new ThemeDescription(this.writeButton, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_profile_actionPressedBackground), new ThemeDescription(this.listView, 0, new Class[]{GraySectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_graySectionText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{GraySectionCell.class}, null, null, null, Theme.key_graySection), new ThemeDescription(this.listView, 0, new Class[]{SettingsSearchCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{SettingsSearchCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, 0, new Class[]{SettingsSearchCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon)};
    }
}
