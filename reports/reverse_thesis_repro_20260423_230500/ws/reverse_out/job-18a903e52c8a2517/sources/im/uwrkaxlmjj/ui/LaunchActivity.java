package im.uwrkaxlmjj.ui;

import android.app.ActivityManager;
import android.app.NotificationManager;
import android.app.role.RoleManager;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.StatFs;
import android.text.TextUtils;
import android.util.Base64;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.Window;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.view.PointerIconCompat;
import com.bjz.comm.net.utils.AppPreferenceUtil;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.google.android.gms.common.api.Status;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.javaBean.fc.FollowedFcListBean;
import im.uwrkaxlmjj.javaBean.fc.HomeFcListBean;
import im.uwrkaxlmjj.javaBean.fc.RecommendFcListBean;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.LocationController;
import im.uwrkaxlmjj.messenger.MediaController;
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
import im.uwrkaxlmjj.messenger.camera.CameraController;
import im.uwrkaxlmjj.messenger.utils.PlayerUtils;
import im.uwrkaxlmjj.tel.CallApiBelow26And28Service;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCCall;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.PhoneBookSelectActivity;
import im.uwrkaxlmjj.ui.WallpapersListActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBarLayout;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.DrawerLayoutContainer;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.adapters.DrawerLayoutAdapter;
import im.uwrkaxlmjj.ui.cells.DrawerUserCell;
import im.uwrkaxlmjj.ui.cells.LanguageCell;
import im.uwrkaxlmjj.ui.cells.ThemesHorizontalListCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.BlockingUpdateView;
import im.uwrkaxlmjj.ui.components.EmbedBottomSheet;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.PasscodeView;
import im.uwrkaxlmjj.ui.components.PipRoundVideoView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.StickersAlert;
import im.uwrkaxlmjj.ui.components.TermsOfServiceView;
import im.uwrkaxlmjj.ui.components.ThemeEditorView;
import im.uwrkaxlmjj.ui.components.UpdateAppAlertDialog;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import im.uwrkaxlmjj.ui.hui.discoveryweb.DiscoveryJumpPausedFloatingView;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.helper.DatabaseInstance;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.helper.FcDBHelper;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity;
import im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity;
import im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.hui.visualcall.RingUtils;
import im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity;
import im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity;
import im.uwrkaxlmjj.ui.hui.visualcall.VisualCallRequestParaBean;
import im.uwrkaxlmjj.ui.utils.AppUpdater;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class LaunchActivity extends AppCompatActivity implements ActionBarLayout.ActionBarLayoutDelegate, NotificationCenter.NotificationCenterDelegate, DialogsActivity.DialogsActivityDelegate {
    private static final int CODE = 102;
    private static final int PLAY_SERVICES_REQUEST_CHECK_SETTINGS = 140;
    private ActionBarLayout actionBarLayout;
    private View backgroundTablet;
    private BlockingUpdateView blockingUpdateView;
    private AlertDialog checkUpdateDialog;
    private ArrayList<TLRPC.User> contactsToSend;
    private Uri contactsToSendUri;
    private int currentAccount;
    private int currentConnectionState;
    private String documentsMimeType;
    private ArrayList<String> documentsOriginalPathsArray;
    private ArrayList<String> documentsPathsArray;
    private ArrayList<Uri> documentsUrisArray;
    private DrawerLayoutAdapter drawerLayoutAdapter;
    protected DrawerLayoutContainer drawerLayoutContainer;
    private HashMap<String, String> englishLocaleStrings;
    private boolean finished;
    private ActionBarLayout layersActionBarLayout;
    private boolean loadingLocaleDialog;
    private TLRPC.TL_theme loadingTheme;
    private String loadingThemeFileName;
    private Theme.ThemeInfo loadingThemeInfo;
    private AlertDialog loadingThemeProgressDialog;
    private String loadingThemeWallpaperName;
    private AlertDialog localeDialog;
    private Runnable lockRunnable;
    private byte mBytJumpFromBack = 0;
    private ViewTreeObserver.OnGlobalLayoutListener onGlobalLayoutListener;
    private Intent passcodeSaveIntent;
    private boolean passcodeSaveIntentIsNew;
    private boolean passcodeSaveIntentIsRestore;
    private PasscodeView passcodeView;
    private ArrayList<SendMessagesHelper.SendingMediaInfo> photoPathsArray;
    private AlertDialog proxyErrorDialog;
    private ActionBarLayout rightActionBarLayout;
    private String sendingText;
    private FrameLayout shadowTablet;
    private FrameLayout shadowTabletSide;
    private RecyclerListView sideMenu;
    private HashMap<String, String> systemLocaleStrings;
    private boolean tabletFullSize;
    private TermsOfServiceView termsOfServiceView;
    private UpdateAppAlertDialog updateAppAlertDialog;
    private String videoPath;
    private ActionMode visibleActionMode;
    private AlertDialog visibleDialog;
    private static ArrayList<BaseFragment> mainFragmentsStack = new ArrayList<>();
    private static ArrayList<BaseFragment> layerFragmentsStack = new ArrayList<>();
    private static ArrayList<BaseFragment> rightFragmentsStack = new ArrayList<>();

    private void checkPermission() {
        ArrayList<String> pers = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= 29) {
            RoleManager roleManager = (RoleManager) getSystemService("role");
            startActivityIfNeeded(roleManager.createRequestRoleIntent("android.app.role.CALL_SCREENING"), PointerIconCompat.TYPE_COPY, null);
        } else {
            pers.add("android.permission.READ_PHONE_STATE");
            pers.add("android.permission.MODIFY_PHONE_STATE");
            pers.add("android.permission.PROCESS_OUTGOING_CALLS");
            pers.add("android.permission.WRITE_SECURE_SETTINGS");
            if (Build.VERSION.SDK_INT >= 26) {
                pers.add("android.permission.ANSWER_PHONE_CALLS");
                pers.add("android.permission.MANAGE_OWN_CALLS");
                pers.add("android.permission.READ_PHONE_NUMBERS");
            }
            if (Build.VERSION.SDK_INT >= 30) {
                pers.add("android.permission.QUERY_ALL_PACKAGES");
            }
        }
        ArrayList<String> realPers = new ArrayList<>();
        for (String realPer : pers) {
            if (ActivityCompat.checkSelfPermission(this, realPer) != 0) {
                realPers.add(realPer);
            }
        }
        if (!realPers.isEmpty()) {
            String[] arr = new String[0];
            if (Build.VERSION.SDK_INT >= 23) {
                requestPermissions((String[]) realPers.toArray(arr), 102);
            }
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:95:0x03e6  */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected void onCreate(android.os.Bundle r15) {
        /*
            Method dump skipped, instruction units count: 1444
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.LaunchActivity.onCreate(android.os.Bundle):void");
    }

    public /* synthetic */ boolean lambda$onCreate$0$LaunchActivity(View v, MotionEvent event) {
        if (this.actionBarLayout.fragmentsStack.isEmpty() || event.getAction() != 1) {
            return false;
        }
        float x = event.getX();
        float y = event.getY();
        int[] location = new int[2];
        this.layersActionBarLayout.getLocationOnScreen(location);
        int viewX = location[0];
        int viewY = location[1];
        if (this.layersActionBarLayout.checkTransitionAnimation() || (x > viewX && x < this.layersActionBarLayout.getWidth() + viewX && y > viewY && y < this.layersActionBarLayout.getHeight() + viewY)) {
            return false;
        }
        if (!this.layersActionBarLayout.fragmentsStack.isEmpty()) {
            for (int a = 0; a < this.layersActionBarLayout.fragmentsStack.size() - 1; a = (a - 1) + 1) {
                ActionBarLayout actionBarLayout = this.layersActionBarLayout;
                actionBarLayout.removeFragmentFromStack(actionBarLayout.fragmentsStack.get(0));
            }
            this.layersActionBarLayout.closeLastFragment(true);
        }
        return true;
    }

    static /* synthetic */ void lambda$onCreate$1(View v) {
    }

    static /* synthetic */ void lambda$onCreate$2(View view) {
        int height = view.getMeasuredHeight();
        FileLog.d("height = " + height + " displayHeight = " + AndroidUtilities.displaySize.y);
        if (Build.VERSION.SDK_INT >= 21) {
            height -= AndroidUtilities.statusBarHeight;
        }
        if (height > AndroidUtilities.dp(100.0f) && height < AndroidUtilities.displaySize.y && AndroidUtilities.dp(100.0f) + height > AndroidUtilities.displaySize.y) {
            AndroidUtilities.displaySize.y = height;
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("fix display size y to " + AndroidUtilities.displaySize.y);
            }
        }
    }

    private void checkSystemBarColors() {
        checkSystemBarColors(true);
    }

    private void checkSystemBarColors(boolean checkNavigationBar) {
        if (Build.VERSION.SDK_INT >= 23 && Build.VERSION.SDK_INT >= 26 && checkNavigationBar) {
            Window window = getWindow();
            int color = Theme.getColor(Theme.key_windowBackgroundGray);
            if (window.getNavigationBarColor() != color) {
                window.setNavigationBarColor(color);
                float brightness = AndroidUtilities.computePerceivedBrightness(color);
                AndroidUtilities.setLightNavigationBar(getWindow(), brightness >= 0.721f);
            }
        }
    }

    public void switchToAccount(int account, boolean removeAll) {
        if (account == UserConfig.selectedAccount) {
            return;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("Launch ===> switchToAccount start  newAccount = " + account + " oldAccount = " + this.currentAccount + " userConfigAccount = " + UserConfig.selectedAccount + " removeAll = " + removeAll);
        }
        ConnectionsManager.getInstance(this.currentAccount).setAppPaused(true, false);
        UserConfig.selectedAccount = account;
        UserConfig.getInstance(0).saveConfig(false);
        checkCurrentAccount();
        if (AndroidUtilities.isTablet()) {
            this.layersActionBarLayout.removeAllFragments();
            this.rightActionBarLayout.removeAllFragments();
            if (!this.tabletFullSize) {
                this.shadowTabletSide.setVisibility(0);
                if (this.rightActionBarLayout.fragmentsStack.isEmpty()) {
                    this.backgroundTablet.setVisibility(0);
                }
                this.rightActionBarLayout.setVisibility(8);
            }
            this.layersActionBarLayout.setVisibility(8);
        }
        if (removeAll) {
            this.actionBarLayout.removeAllFragments();
        } else {
            this.actionBarLayout.removeFragmentFromStack(0);
        }
        IndexActivity indexActivity = new IndexActivity();
        this.actionBarLayout.addFragmentToStack(indexActivity, 0);
        this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
        this.actionBarLayout.showLastFragment();
        if (AndroidUtilities.isTablet()) {
            this.layersActionBarLayout.showLastFragment();
            this.rightActionBarLayout.showLastFragment();
        }
        if (!ApplicationLoader.mainInterfacePaused) {
            ConnectionsManager.getInstance(this.currentAccount).setAppPaused(false, false);
        }
        if (UserConfig.getInstance(account).unacceptedTermsOfService != null) {
            showTosActivity(account, UserConfig.getInstance(account).unacceptedTermsOfService);
        }
        AppPreferenceUtil.putString("PublishFcBean", "");
        FcDBHelper.getInstance().deleteAll(HomeFcListBean.class);
        FcDBHelper.getInstance().deleteAll(RecommendFcListBean.class);
        FcDBHelper.getInstance().deleteAll(FollowedFcListBean.class);
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("Launch ===> switchToAccount end  newAccount = " + account + " oldAccount =   = " + this.currentAccount + " userConfigAccount = " + UserConfig.selectedAccount + " removeAll = " + removeAll);
        }
        DiscoveryJumpPausedFloatingView.getInstance().hide(true);
    }

    private void switchToAvailableAccountOrLogout() {
        int account = -1;
        int a = 0;
        while (true) {
            if (a >= 3) {
                break;
            }
            if (!UserConfig.getInstance(a).isClientActivated()) {
                a++;
            } else {
                account = a;
                break;
            }
        }
        TermsOfServiceView termsOfServiceView = this.termsOfServiceView;
        if (termsOfServiceView != null) {
            termsOfServiceView.setVisibility(8);
        }
        if (account != -1) {
            switchToAccount(account, true);
            return;
        }
        ConnectionsManager.getInstance(this.currentAccount).setAppPaused(true, false);
        UserConfig.selectedAccount = 0;
        UserConfig.getInstance(0).saveConfig(false);
        checkCurrentAccount();
        if (AndroidUtilities.isTablet()) {
            this.layersActionBarLayout.removeAllFragments();
            this.rightActionBarLayout.removeAllFragments();
            if (!this.tabletFullSize) {
                this.shadowTabletSide.setVisibility(0);
                if (this.rightActionBarLayout.fragmentsStack.isEmpty()) {
                    this.backgroundTablet.setVisibility(0);
                }
                this.rightActionBarLayout.setVisibility(8);
            }
            this.layersActionBarLayout.setVisibility(8);
        }
        this.actionBarLayout.removeAllFragments();
        LoginContronllerActivity loginPage = new LoginContronllerActivity();
        this.actionBarLayout.addFragmentToStack(loginPage, 0);
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("LaunchActivity ===> switchToAvailableAccountOrLogout() , logoutAccount = 0 UserConfig.selectedAccount = " + UserConfig.selectedAccount + " This.currentAccount = " + this.currentAccount);
        }
        this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
        this.actionBarLayout.showLastFragment();
        if (AndroidUtilities.isTablet()) {
            this.layersActionBarLayout.showLastFragment();
            this.rightActionBarLayout.showLastFragment();
        }
        if (!ApplicationLoader.mainInterfacePaused) {
            ConnectionsManager.getInstance(this.currentAccount).setAppPaused(false, false);
        }
    }

    public int getMainFragmentsCount() {
        return mainFragmentsStack.size();
    }

    private void checkCurrentAccount() {
        if (this.currentAccount != UserConfig.selectedAccount) {
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.appDidLogout);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.mainUserInfoChanged);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didUpdateConnectionState);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.needShowAlert);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.wasUnableToFindCurrentLocation);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.openArticle);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.hasNewContactsToImport);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.needShowPlayServicesAlert);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileDidLoad);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileDidFailToLoad);
            NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.folderWebView);
        }
        int i = UserConfig.selectedAccount;
        this.currentAccount = i;
        NotificationCenter.getInstance(i).addObserver(this, NotificationCenter.appDidLogout);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.mainUserInfoChanged);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.didUpdateConnectionState);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.needShowAlert);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.wasUnableToFindCurrentLocation);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.openArticle);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.hasNewContactsToImport);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.needShowPlayServicesAlert);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileDidFailToLoad);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.folderWebView);
        updateCurrentConnectionState(this.currentAccount);
    }

    private void checkLayout() {
        if (!AndroidUtilities.isTablet() || this.rightActionBarLayout == null) {
            return;
        }
        if (!AndroidUtilities.isInMultiwindow && (!AndroidUtilities.isSmallTablet() || getResources().getConfiguration().orientation == 2)) {
            this.tabletFullSize = false;
            if (this.actionBarLayout.fragmentsStack.size() >= 2) {
                for (int a = 1; a < this.actionBarLayout.fragmentsStack.size(); a = (a - 1) + 1) {
                    BaseFragment chatFragment = this.actionBarLayout.fragmentsStack.get(a);
                    if (chatFragment instanceof ChatActivity) {
                        ((ChatActivity) chatFragment).setIgnoreAttachOnPause(true);
                    }
                    chatFragment.onPause();
                    this.actionBarLayout.fragmentsStack.remove(a);
                    this.rightActionBarLayout.fragmentsStack.add(chatFragment);
                }
                if (this.passcodeView.getVisibility() != 0) {
                    this.actionBarLayout.showLastFragment();
                    this.rightActionBarLayout.showLastFragment();
                }
            }
            ActionBarLayout actionBarLayout = this.rightActionBarLayout;
            actionBarLayout.setVisibility(actionBarLayout.fragmentsStack.isEmpty() ? 8 : 0);
            this.backgroundTablet.setVisibility(this.rightActionBarLayout.fragmentsStack.isEmpty() ? 0 : 8);
            this.shadowTabletSide.setVisibility(this.actionBarLayout.fragmentsStack.isEmpty() ? 8 : 0);
            return;
        }
        this.tabletFullSize = true;
        if (!this.rightActionBarLayout.fragmentsStack.isEmpty()) {
            for (int a2 = 0; a2 < this.rightActionBarLayout.fragmentsStack.size(); a2 = (a2 - 1) + 1) {
                BaseFragment chatFragment2 = this.rightActionBarLayout.fragmentsStack.get(a2);
                if (chatFragment2 instanceof ChatActivity) {
                    ((ChatActivity) chatFragment2).setIgnoreAttachOnPause(true);
                }
                chatFragment2.onPause();
                this.rightActionBarLayout.fragmentsStack.remove(a2);
                this.actionBarLayout.fragmentsStack.add(chatFragment2);
            }
            if (this.passcodeView.getVisibility() != 0) {
                this.actionBarLayout.showLastFragment();
            }
        }
        this.shadowTabletSide.setVisibility(8);
        this.rightActionBarLayout.setVisibility(8);
        this.backgroundTablet.setVisibility(this.actionBarLayout.fragmentsStack.isEmpty() ? 0 : 8);
    }

    private void showUpdateActivity(int account, TLRPC.TL_help_appUpdate update, boolean check) {
        if (this.blockingUpdateView == null) {
            BlockingUpdateView blockingUpdateView = new BlockingUpdateView(this) { // from class: im.uwrkaxlmjj.ui.LaunchActivity.2
                @Override // im.uwrkaxlmjj.ui.components.BlockingUpdateView, android.view.View
                public void setVisibility(int visibility) {
                    super.setVisibility(visibility);
                    if (visibility == 8) {
                        LaunchActivity.this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
                    }
                }
            };
            this.blockingUpdateView = blockingUpdateView;
            this.drawerLayoutContainer.addView(blockingUpdateView, LayoutHelper.createFrame(-1, -1.0f));
        }
        this.blockingUpdateView.show(account, update, check);
        this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
    }

    private void showTosActivity(int account, TLRPC.TL_help_termsOfService tos) {
        if (this.termsOfServiceView == null) {
            TermsOfServiceView termsOfServiceView = new TermsOfServiceView(this);
            this.termsOfServiceView = termsOfServiceView;
            this.drawerLayoutContainer.addView(termsOfServiceView, LayoutHelper.createFrame(-1, -1.0f));
            this.termsOfServiceView.setDelegate(new TermsOfServiceView.TermsOfServiceViewDelegate() { // from class: im.uwrkaxlmjj.ui.LaunchActivity.3
                @Override // im.uwrkaxlmjj.ui.components.TermsOfServiceView.TermsOfServiceViewDelegate
                public void onAcceptTerms(int account2) {
                    UserConfig.getInstance(account2).unacceptedTermsOfService = null;
                    UserConfig.getInstance(account2).saveConfig(false);
                    LaunchActivity.this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
                    LaunchActivity.this.termsOfServiceView.setVisibility(8);
                }

                @Override // im.uwrkaxlmjj.ui.components.TermsOfServiceView.TermsOfServiceViewDelegate
                public void onDeclineTerms(int account2) {
                    LaunchActivity.this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
                    LaunchActivity.this.termsOfServiceView.setVisibility(8);
                }
            });
        }
        TLRPC.TL_help_termsOfService currentTos = UserConfig.getInstance(account).unacceptedTermsOfService;
        if (currentTos != tos && (currentTos == null || !currentTos.id.data.equals(tos.id.data))) {
            UserConfig.getInstance(account).unacceptedTermsOfService = tos;
            UserConfig.getInstance(account).saveConfig(false);
        }
        this.termsOfServiceView.show(account, tos);
        this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showPasscodeActivity() {
        if (this.passcodeView == null) {
            return;
        }
        SharedConfig.appLocked = true;
        if (SecretMediaViewer.hasInstance() && SecretMediaViewer.getInstance().isVisible()) {
            SecretMediaViewer.getInstance().closePhoto(false, false);
        } else if (PhotoViewer.hasInstance() && PhotoViewer.getInstance().isVisible()) {
            PhotoViewer.getInstance().closePhoto(false, true);
        } else if (ArticleViewer.hasInstance() && ArticleViewer.getInstance().isVisible()) {
            ArticleViewer.getInstance().close(false, true);
        }
        this.passcodeView.onShow();
        SharedConfig.isWaitingForPasscodeEnter = true;
        this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
        this.passcodeView.setDelegate(new PasscodeView.PasscodeViewDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$sNeL6cFGNs1uWzfGYrrTF6fSm1s
            @Override // im.uwrkaxlmjj.ui.components.PasscodeView.PasscodeViewDelegate
            public final void didAcceptedPassword() {
                this.f$0.lambda$showPasscodeActivity$3$LaunchActivity();
            }
        });
        this.actionBarLayout.setVisibility(4);
        if (AndroidUtilities.isTablet()) {
            if (this.layersActionBarLayout.getVisibility() == 0) {
                this.layersActionBarLayout.setVisibility(4);
            }
            this.rightActionBarLayout.setVisibility(4);
        }
    }

    public /* synthetic */ void lambda$showPasscodeActivity$3$LaunchActivity() {
        SharedConfig.isWaitingForPasscodeEnter = false;
        Intent intent = this.passcodeSaveIntent;
        if (intent != null) {
            handleIntent(intent, this.passcodeSaveIntentIsNew, this.passcodeSaveIntentIsRestore, true);
            this.passcodeSaveIntent = null;
        }
        this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
        this.actionBarLayout.setVisibility(0);
        this.actionBarLayout.showLastFragment();
        if (AndroidUtilities.isTablet()) {
            this.layersActionBarLayout.showLastFragment();
            this.rightActionBarLayout.showLastFragment();
            if (this.layersActionBarLayout.getVisibility() == 4) {
                this.layersActionBarLayout.setVisibility(0);
            }
            this.rightActionBarLayout.setVisibility(0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:147:0x02ac  */
    /* JADX WARN: Removed duplicated region for block: B:190:0x0376  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x0385  */
    /* JADX WARN: Removed duplicated region for block: B:551:0x0ded  */
    /* JADX WARN: Removed duplicated region for block: B:555:0x0e01  */
    /* JADX WARN: Removed duplicated region for block: B:658:0x1085  */
    /* JADX WARN: Removed duplicated region for block: B:666:0x10ba  */
    /* JADX WARN: Removed duplicated region for block: B:679:0x1107  */
    /* JADX WARN: Removed duplicated region for block: B:765:0x133c  */
    /* JADX WARN: Removed duplicated region for block: B:768:0x1341 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:771:0x1349  */
    /* JADX WARN: Removed duplicated region for block: B:779:0x1389  */
    /* JADX WARN: Removed duplicated region for block: B:787:0x13c9  */
    /* JADX WARN: Type inference failed for: r2v11 */
    /* JADX WARN: Type inference failed for: r2v12 */
    /* JADX WARN: Type inference failed for: r2v13 */
    /* JADX WARN: Type inference failed for: r2v149 */
    /* JADX WARN: Type inference failed for: r2v15 */
    /* JADX WARN: Type inference failed for: r2v150 */
    /* JADX WARN: Type inference failed for: r2v151 */
    /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't find top splitter block for handler:B:474:0x0bf9
        	at jadx.core.utils.BlockUtils.getTopSplitterForHandler(BlockUtils.java:1182)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.collectHandlerRegions(ExcHandlersRegionMaker.java:53)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.process(ExcHandlersRegionMaker.java:38)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:27)
        */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean handleIntent(android.content.Intent r66, boolean r67, boolean r68, boolean r69) {
        /*
            Method dump skipped, instruction units count: 5079
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.LaunchActivity.handleIntent(android.content.Intent, boolean, boolean, boolean):boolean");
    }

    public /* synthetic */ void lambda$handleIntent$4$LaunchActivity(Bundle args) {
        lambda$runLinkRequest$26$LaunchActivity(new CancelAccountDeletionActivity(args));
    }

    private void getUserInfo(TLRPC.User user) {
        TLRPC.TL_users_getFullUser req = new TLRPC.TL_users_getFullUser();
        req.id = MessagesController.getInstance(UserConfig.selectedAccount).getInputUser(user);
        final XAlertDialog progressDialog = new XAlertDialog(this, 4);
        progressDialog.setLoadingText(LocaleController.getString(R.string.Loading));
        int reqId = ConnectionsManager.getInstance(UserConfig.selectedAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$lVN-X2ZOpihL7uwd2JsgrhflWwY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getUserInfo$6$LaunchActivity(progressDialog, tLObject, tL_error);
            }
        });
        progressDialog.show();
        ConnectionsManager.getInstance(UserConfig.selectedAccount).bindRequestToGuid(reqId, getActionBarLayout().getCurrentFragment().getClassGuid());
    }

    public /* synthetic */ void lambda$getUserInfo$6$LaunchActivity(XAlertDialog progressDialog, final TLObject response, TLRPC.TL_error error) {
        progressDialog.dismiss();
        if (error == null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$NQGbCjak9uc9fb2Jq7x5hqjGRnA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$5$LaunchActivity(response);
                }
            });
        } else if ("USERNOTEXITST".equals(error.text)) {
            AlertsCreator.showSimpleAlert(getActionBarLayout().getCurrentFragment(), LocaleController.getString("UserNotExist", R.string.UserNotExist));
        }
    }

    public /* synthetic */ void lambda$null$5$LaunchActivity(TLObject response) {
        TLRPC.UserFull userFull = (TLRPC.UserFull) response;
        MessagesController.getInstance(UserConfig.selectedAccount).putUser(userFull.user, false);
        if (userFull.user == null) {
            return;
        }
        if (userFull.user.self || userFull.user.contact) {
            Bundle bundle = new Bundle();
            bundle.putInt("user_id", userFull.user.id);
            lambda$runLinkRequest$26$LaunchActivity(new NewProfileActivity(bundle));
        } else {
            Bundle bundle2 = new Bundle();
            bundle2.putInt("from_type", 4);
            lambda$runLinkRequest$26$LaunchActivity(new AddContactsInfoActivity(bundle2, userFull.user));
        }
    }

    private void runLinkRequest(final int intentAccount, final String username, final String group, final String sticker, final String botUser, final String botChat, final String message, final boolean hasUrl, final Integer messageId, final Integer channelId, final String game, final HashMap<String, String> auth, final String lang, final String unsupportedUrl, final String code, final TLRPC.TL_wallPaper wallPaper, final String theme, int state) {
        final int i;
        final int[] requestId;
        final AlertDialog progressDialog;
        if (state == 0 && UserConfig.getActivatedAccountsCount() >= 2 && auth != null) {
            AlertsCreator.createAccountSelectDialog(this, new AlertsCreator.AccountSelectDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$P9rWkvUmOotx7TutIOM7zNgxz7Q
                @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.AccountSelectDelegate
                public final void didSelectAccount(int i2) {
                    this.f$0.lambda$runLinkRequest$7$LaunchActivity(intentAccount, username, group, sticker, botUser, botChat, message, hasUrl, messageId, channelId, game, auth, lang, unsupportedUrl, code, wallPaper, theme, i2);
                }
            }).show();
            return;
        }
        BaseFragment baseFragment = null;
        if (code == null) {
            final AlertDialog progressDialog2 = new AlertDialog(this, 3);
            int[] requestId2 = {0};
            Runnable cancelRunnable = null;
            if (username != null) {
                TLRPC.TL_contacts_resolveUsername req = new TLRPC.TL_contacts_resolveUsername();
                req.username = username;
                requestId2[0] = ConnectionsManager.getInstance(intentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$O_K-ooQ0Pe6PUA57zl56Tz5N1GY
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$runLinkRequest$11$LaunchActivity(progressDialog2, game, intentAccount, botChat, botUser, messageId, tLObject, tL_error);
                    }
                });
                requestId = requestId2;
                progressDialog = progressDialog2;
                i = intentAccount;
            } else if (group == null) {
                i = intentAccount;
                requestId = requestId2;
                if (sticker != null) {
                    if (!mainFragmentsStack.isEmpty()) {
                        TLRPC.TL_inputStickerSetShortName stickerset = new TLRPC.TL_inputStickerSetShortName();
                        stickerset.short_name = sticker;
                        ArrayList<BaseFragment> arrayList = mainFragmentsStack;
                        BaseFragment fragment = arrayList.get(arrayList.size() - 1);
                        fragment.showDialog(new StickersAlert(this, fragment, stickerset, null, null));
                        return;
                    }
                    return;
                }
                if (message != null) {
                    Bundle args = new Bundle();
                    args.putBoolean("onlySelect", true);
                    DialogsActivity fragment2 = new DialogsActivity(args);
                    fragment2.setDelegate(new DialogsActivity.DialogsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$_7dzOoYmz-bYmmRdKAHz7rl6BKo
                        @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
                        public final void didSelectDialogs(DialogsActivity dialogsActivity, ArrayList arrayList2, CharSequence charSequence, boolean z) {
                            this.f$0.lambda$runLinkRequest$17$LaunchActivity(hasUrl, i, message, dialogsActivity, arrayList2, charSequence, z);
                        }
                    });
                    presentFragment(fragment2, false, true);
                    progressDialog = progressDialog2;
                } else if (auth == null) {
                    progressDialog = progressDialog2;
                    if (unsupportedUrl != null) {
                        TLRPC.TL_help_getDeepLinkInfo req2 = new TLRPC.TL_help_getDeepLinkInfo();
                        req2.path = unsupportedUrl;
                        requestId[0] = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$o2j9bH1ED-D13wQbEUAYKfuX9jk
                            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                this.f$0.lambda$runLinkRequest$23$LaunchActivity(progressDialog, tLObject, tL_error);
                            }
                        });
                    } else if (lang != null) {
                        TLRPC.TL_langpack_getLanguage req3 = new TLRPC.TL_langpack_getLanguage();
                        req3.lang_code = lang;
                        req3.lang_pack = "android";
                        requestId[0] = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req3, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$gTlFFl7WP47L-wjv_Sm4Jq0Q2hg
                            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                this.f$0.lambda$runLinkRequest$25$LaunchActivity(progressDialog, tLObject, tL_error);
                            }
                        });
                    } else if (wallPaper != null) {
                        boolean ok = false;
                        if (TextUtils.isEmpty(wallPaper.slug)) {
                            try {
                                WallpapersListActivity.ColorWallpaper colorWallpaper = new WallpapersListActivity.ColorWallpaper(-100L, wallPaper.settings.background_color);
                                final WallpaperActivity wallpaperActivity = new WallpaperActivity(colorWallpaper, null);
                                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$Za1fhYeKsfM_HADbtQdmWKOrZls
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        this.f$0.lambda$runLinkRequest$26$LaunchActivity(wallpaperActivity);
                                    }
                                });
                                ok = true;
                            } catch (Exception e) {
                                FileLog.e(e);
                            }
                        }
                        if (!ok) {
                            TLRPC.TL_account_getWallPaper req4 = new TLRPC.TL_account_getWallPaper();
                            TLRPC.TL_inputWallPaperSlug inputWallPaperSlug = new TLRPC.TL_inputWallPaperSlug();
                            inputWallPaperSlug.slug = wallPaper.slug;
                            req4.wallpaper = inputWallPaperSlug;
                            requestId[0] = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req4, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$Ibh8UrSSxL8Z55AVSwVYCgwNs_Q
                                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                    this.f$0.lambda$runLinkRequest$28$LaunchActivity(progressDialog, wallPaper, tLObject, tL_error);
                                }
                            });
                        }
                    } else if (theme != null) {
                        Runnable cancelRunnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$uLPh0oC7VNbdPEOqqCfjhOwWvXw
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$runLinkRequest$29$LaunchActivity();
                            }
                        };
                        TLRPC.TL_account_getTheme req5 = new TLRPC.TL_account_getTheme();
                        req5.format = "android";
                        TLRPC.TL_inputThemeSlug inputThemeSlug = new TLRPC.TL_inputThemeSlug();
                        inputThemeSlug.slug = theme;
                        req5.theme = inputThemeSlug;
                        requestId[0] = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req5, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$zBa1uaUx7SYiRHdHBMJYbgVNC9I
                            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                this.f$0.lambda$runLinkRequest$31$LaunchActivity(progressDialog, tLObject, tL_error);
                            }
                        });
                        cancelRunnable = cancelRunnable2;
                    } else if (channelId != null && messageId != null) {
                        final Bundle args2 = new Bundle();
                        args2.putInt("chat_id", channelId.intValue());
                        args2.putInt("message_id", messageId.intValue());
                        if (!mainFragmentsStack.isEmpty()) {
                            ArrayList<BaseFragment> arrayList2 = mainFragmentsStack;
                            baseFragment = arrayList2.get(arrayList2.size() - 1);
                        }
                        final BaseFragment lastFragment = baseFragment;
                        if (lastFragment == null || MessagesController.getInstance(intentAccount).checkCanOpenChat(args2, lastFragment)) {
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$MqeRpY5JLvfuFkZIs4x3dtOfce8
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$runLinkRequest$34$LaunchActivity(args2, channelId, requestId, progressDialog, lastFragment, intentAccount);
                                }
                            });
                        }
                    }
                } else {
                    int bot_id = Utilities.parseInt(auth.get("bot_id")).intValue();
                    if (bot_id == 0) {
                        return;
                    }
                    final String payload = auth.get("payload");
                    final String nonce = auth.get("nonce");
                    final String callbackUrl = auth.get("callback_url");
                    final TLRPC.TL_account_getAuthorizationForm req6 = new TLRPC.TL_account_getAuthorizationForm();
                    req6.bot_id = bot_id;
                    req6.scope = auth.get("scope");
                    req6.public_key = auth.get("public_key");
                    progressDialog = progressDialog2;
                    requestId[0] = ConnectionsManager.getInstance(intentAccount).sendRequest(req6, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$kMH6FWmxiM11wFoFwdjNex2bMiE
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$runLinkRequest$21$LaunchActivity(requestId, intentAccount, progressDialog2, req6, payload, nonce, callbackUrl, tLObject, tL_error);
                        }
                    });
                }
            } else if (state == 0) {
                TLRPC.TL_messages_checkChatInvite req7 = new TLRPC.TL_messages_checkChatInvite();
                req7.hash = group;
                requestId = requestId2;
                requestId[0] = ConnectionsManager.getInstance(intentAccount).sendRequest(req7, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$4oRpJNSdLSFymCjXvVxNwDxi1N8
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$runLinkRequest$14$LaunchActivity(progressDialog2, intentAccount, group, username, sticker, botUser, botChat, message, hasUrl, messageId, channelId, game, auth, lang, unsupportedUrl, code, wallPaper, theme, tLObject, tL_error);
                    }
                }, 2);
                i = intentAccount;
                progressDialog = progressDialog2;
            } else {
                requestId = requestId2;
                if (state == 1) {
                    TLRPC.TL_messages_importChatInvite req8 = new TLRPC.TL_messages_importChatInvite();
                    req8.hash = group;
                    i = intentAccount;
                    ConnectionsManager.getInstance(intentAccount).sendRequest(req8, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$KMT0fh-9sZ4bVtCdkLURTO4O9tc
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$runLinkRequest$16$LaunchActivity(i, progressDialog2, tLObject, tL_error);
                        }
                    }, 2);
                    progressDialog = progressDialog2;
                } else {
                    i = intentAccount;
                    progressDialog = progressDialog2;
                }
            }
            if (requestId[0] != 0) {
                final Runnable cancelRunnableFinal = cancelRunnable;
                progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$ytPnDgOK1cY9QSf8GfclMhM1PkI
                    @Override // android.content.DialogInterface.OnCancelListener
                    public final void onCancel(DialogInterface dialogInterface) {
                        LaunchActivity.lambda$runLinkRequest$35(i, requestId, cancelRunnableFinal, dialogInterface);
                    }
                });
                try {
                    progressDialog.show();
                    return;
                } catch (Exception e2) {
                    return;
                }
            }
            return;
        }
        if (!NotificationCenter.getGlobalInstance().hasObservers(NotificationCenter.didReceiveSmsCode)) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("OtherLoginCode", R.string.OtherLoginCode, code)));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            showAlertDialog(builder);
            return;
        }
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.didReceiveSmsCode, code);
    }

    public /* synthetic */ void lambda$runLinkRequest$7$LaunchActivity(int intentAccount, String username, String group, String sticker, String botUser, String botChat, String message, boolean hasUrl, Integer messageId, Integer channelId, String game, HashMap auth, String lang, String unsupportedUrl, String code, TLRPC.TL_wallPaper wallPaper, String theme, int account) {
        if (account != intentAccount) {
            switchToAccount(account, true);
        }
        runLinkRequest(account, username, group, sticker, botUser, botChat, message, hasUrl, messageId, channelId, game, auth, lang, unsupportedUrl, code, wallPaper, theme, 1);
    }

    public /* synthetic */ void lambda$runLinkRequest$11$LaunchActivity(final AlertDialog progressDialog, final String game, final int intentAccount, final String botChat, final String botUser, final Integer messageId, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$wN_mWH0ZhpZAvoJcsfc_Y_URSAg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$10$LaunchActivity(progressDialog, response, error, game, intentAccount, botChat, botUser, messageId);
            }
        });
    }

    public /* synthetic */ void lambda$null$10$LaunchActivity(AlertDialog alertDialog, TLObject tLObject, TLRPC.TL_error tL_error, final String str, final int i, final String str2, String str3, Integer num) {
        long j;
        boolean z;
        if (!isFinishing()) {
            try {
                alertDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
            final TLRPC.TL_contacts_resolvedPeer tL_contacts_resolvedPeer = (TLRPC.TL_contacts_resolvedPeer) tLObject;
            if (tL_error != null || this.actionBarLayout == null || (str != null && (str == null || tL_contacts_resolvedPeer.users.isEmpty()))) {
                try {
                    AlertsCreator.createSimpleAlert(this, LocaleController.getString("JoinToGroupErrorNotExist", R.string.JoinToGroupErrorNotExist)).show();
                    return;
                } catch (Exception e2) {
                    FileLog.e(e2);
                    return;
                }
            }
            MessagesController.getInstance(i).putUsers(tL_contacts_resolvedPeer.users, false);
            MessagesController.getInstance(i).putChats(tL_contacts_resolvedPeer.chats, false);
            MessagesStorage.getInstance(i).putUsersAndChats(tL_contacts_resolvedPeer.users, tL_contacts_resolvedPeer.chats, false, true);
            if (str != null) {
                Bundle bundle = new Bundle();
                bundle.putBoolean("onlySelect", true);
                bundle.putBoolean("cantSendToChannels", true);
                bundle.putInt("dialogsType", 1);
                bundle.putString("selectAlertString", LocaleController.getString("SendGameTo", R.string.SendGameTo));
                bundle.putString("selectAlertStringGroup", LocaleController.getString("SendGameToGroup", R.string.SendGameToGroup));
                DialogsActivity dialogsActivity = new DialogsActivity(bundle);
                dialogsActivity.setDelegate(new DialogsActivity.DialogsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$stA82eXpSQow2zcx3jP0p4J4r4o
                    @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
                    public final void didSelectDialogs(DialogsActivity dialogsActivity2, ArrayList arrayList, CharSequence charSequence, boolean z2) {
                        this.f$0.lambda$null$8$LaunchActivity(str, i, tL_contacts_resolvedPeer, dialogsActivity2, arrayList, charSequence, z2);
                    }
                });
                if (AndroidUtilities.isTablet()) {
                    z = this.layersActionBarLayout.fragmentsStack.size() > 0 && (this.layersActionBarLayout.fragmentsStack.get(this.layersActionBarLayout.fragmentsStack.size() - 1) instanceof IndexActivity);
                } else {
                    z = this.actionBarLayout.fragmentsStack.size() > 1 && (this.actionBarLayout.fragmentsStack.get(this.actionBarLayout.fragmentsStack.size() - 1) instanceof IndexActivity);
                }
                this.actionBarLayout.presentFragment(dialogsActivity, z, true, true, false);
                if (SecretMediaViewer.hasInstance() && SecretMediaViewer.getInstance().isVisible()) {
                    SecretMediaViewer.getInstance().closePhoto(false, false);
                } else if (PhotoViewer.hasInstance() && PhotoViewer.getInstance().isVisible()) {
                    PhotoViewer.getInstance().closePhoto(false, true);
                } else if (ArticleViewer.hasInstance() && ArticleViewer.getInstance().isVisible()) {
                    ArticleViewer.getInstance().close(false, true);
                }
                this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
                if (AndroidUtilities.isTablet()) {
                    this.actionBarLayout.showLastFragment();
                    this.rightActionBarLayout.showLastFragment();
                    return;
                } else {
                    this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
                    return;
                }
            }
            BaseFragment baseFragment = null;
            if (str2 != null) {
                final TLRPC.User user = tL_contacts_resolvedPeer.users.isEmpty() ? null : tL_contacts_resolvedPeer.users.get(0);
                if (user == null || (user.bot && user.bot_nochats)) {
                    try {
                        ToastUtils.show(R.string.BotCantJoinGroups);
                        return;
                    } catch (Exception e3) {
                        FileLog.e(e3);
                        return;
                    }
                }
                Bundle bundle2 = new Bundle();
                bundle2.putBoolean("onlySelect", true);
                bundle2.putInt("dialogsType", 2);
                bundle2.putString("addToGroupAlertString", LocaleController.formatString("AddToTheGroupTitle", R.string.AddToTheGroupTitle, UserObject.getName(user), "%1$s"));
                DialogsActivity dialogsActivity2 = new DialogsActivity(bundle2);
                dialogsActivity2.setDelegate(new DialogsActivity.DialogsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$56yO9grRW7OBOpkRRcV4K2fSztk
                    @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
                    public final void didSelectDialogs(DialogsActivity dialogsActivity3, ArrayList arrayList, CharSequence charSequence, boolean z2) {
                        this.f$0.lambda$null$9$LaunchActivity(i, user, str2, dialogsActivity3, arrayList, charSequence, z2);
                    }
                });
                lambda$runLinkRequest$26$LaunchActivity(dialogsActivity2);
                return;
            }
            boolean z2 = false;
            Bundle bundle3 = new Bundle();
            if (!tL_contacts_resolvedPeer.chats.isEmpty()) {
                bundle3.putInt("chat_id", tL_contacts_resolvedPeer.chats.get(0).id);
                j = -tL_contacts_resolvedPeer.chats.get(0).id;
            } else {
                bundle3.putInt("user_id", tL_contacts_resolvedPeer.users.get(0).id);
                j = tL_contacts_resolvedPeer.users.get(0).id;
            }
            if (str3 != null && tL_contacts_resolvedPeer.users.size() > 0 && tL_contacts_resolvedPeer.users.get(0).bot) {
                bundle3.putString("botUser", str3);
                z2 = true;
            }
            if (num != null) {
                bundle3.putInt("message_id", num.intValue());
            }
            if (!mainFragmentsStack.isEmpty()) {
                ArrayList<BaseFragment> arrayList = mainFragmentsStack;
                baseFragment = arrayList.get(arrayList.size() - 1);
            }
            BaseFragment baseFragment2 = baseFragment;
            if (baseFragment2 == null || MessagesController.getInstance(i).checkCanOpenChat(bundle3, baseFragment2)) {
                if (z2 && (baseFragment2 instanceof ChatActivity) && ((ChatActivity) baseFragment2).getDialogId() == j) {
                    ((ChatActivity) baseFragment2).setBotUser(str3);
                } else {
                    this.actionBarLayout.presentFragment(new ChatActivity(bundle3));
                }
            }
        }
    }

    public /* synthetic */ void lambda$null$8$LaunchActivity(String game, int intentAccount, TLRPC.TL_contacts_resolvedPeer res, DialogsActivity fragment1, ArrayList dids, CharSequence message1, boolean param) {
        long did = ((Long) dids.get(0)).longValue();
        TLRPC.TL_inputMediaGame inputMediaGame = new TLRPC.TL_inputMediaGame();
        inputMediaGame.id = new TLRPC.TL_inputGameShortName();
        inputMediaGame.id.short_name = game;
        inputMediaGame.id.bot_id = MessagesController.getInstance(intentAccount).getInputUser(res.users.get(0));
        SendMessagesHelper.getInstance(intentAccount).sendGame(MessagesController.getInstance(intentAccount).getInputPeer((int) did), inputMediaGame, 0L, 0L);
        Bundle args1 = new Bundle();
        args1.putBoolean("scrollToTopOnResume", true);
        int lower_part = (int) did;
        int high_id = (int) (did >> 32);
        if (lower_part != 0) {
            if (lower_part > 0) {
                args1.putInt("user_id", lower_part);
            } else if (lower_part < 0) {
                args1.putInt("chat_id", -lower_part);
            }
        } else {
            args1.putInt("enc_id", high_id);
        }
        if (MessagesController.getInstance(intentAccount).checkCanOpenChat(args1, fragment1)) {
            NotificationCenter.getInstance(intentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
            this.actionBarLayout.presentFragment(new ChatActivity(args1), true, false, true, false);
        }
    }

    public /* synthetic */ void lambda$null$9$LaunchActivity(int intentAccount, TLRPC.User user, String botChat, DialogsActivity fragment12, ArrayList dids, CharSequence message1, boolean param) {
        long did = ((Long) dids.get(0)).longValue();
        Bundle args12 = new Bundle();
        args12.putBoolean("scrollToTopOnResume", true);
        args12.putInt("chat_id", -((int) did));
        if (!mainFragmentsStack.isEmpty()) {
            MessagesController messagesController = MessagesController.getInstance(intentAccount);
            ArrayList<BaseFragment> arrayList = mainFragmentsStack;
            if (!messagesController.checkCanOpenChat(args12, arrayList.get(arrayList.size() - 1))) {
                return;
            }
        }
        NotificationCenter.getInstance(intentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
        MessagesController.getInstance(intentAccount).addUserToChat(-((int) did), user, null, 0, botChat, null, null);
        this.actionBarLayout.presentFragment(new ChatActivity(args12), true, false, true, false);
    }

    public /* synthetic */ void lambda$runLinkRequest$14$LaunchActivity(final AlertDialog progressDialog, final int intentAccount, final String group, final String username, final String sticker, final String botUser, final String botChat, final String message, final boolean hasUrl, final Integer messageId, final Integer channelId, final String game, final HashMap auth, final String lang, final String unsupportedUrl, final String code, final TLRPC.TL_wallPaper wallPaper, final String theme, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$SKvEtqomWxuxCd4x0t7_g_fKIJ4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$13$LaunchActivity(progressDialog, error, response, intentAccount, group, username, sticker, botUser, botChat, message, hasUrl, messageId, channelId, game, auth, lang, unsupportedUrl, code, wallPaper, theme);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x008e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$null$13$LaunchActivity(im.uwrkaxlmjj.ui.actionbar.AlertDialog r24, im.uwrkaxlmjj.tgnet.TLRPC.TL_error r25, im.uwrkaxlmjj.tgnet.TLObject r26, final int r27, final java.lang.String r28, final java.lang.String r29, final java.lang.String r30, final java.lang.String r31, final java.lang.String r32, final java.lang.String r33, final boolean r34, final java.lang.Integer r35, final java.lang.Integer r36, final java.lang.String r37, final java.util.HashMap r38, final java.lang.String r39, final java.lang.String r40, final java.lang.String r41, final im.uwrkaxlmjj.tgnet.TLRPC.TL_wallPaper r42, final java.lang.String r43) {
        /*
            Method dump skipped, instruction units count: 435
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.LaunchActivity.lambda$null$13$LaunchActivity(im.uwrkaxlmjj.ui.actionbar.AlertDialog, im.uwrkaxlmjj.tgnet.TLRPC$TL_error, im.uwrkaxlmjj.tgnet.TLObject, int, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, boolean, java.lang.Integer, java.lang.Integer, java.lang.String, java.util.HashMap, java.lang.String, java.lang.String, java.lang.String, im.uwrkaxlmjj.tgnet.TLRPC$TL_wallPaper, java.lang.String):void");
    }

    public /* synthetic */ void lambda$null$12$LaunchActivity(int intentAccount, String username, String group, String sticker, String botUser, String botChat, String message, boolean hasUrl, Integer messageId, Integer channelId, String game, HashMap auth, String lang, String unsupportedUrl, String code, TLRPC.TL_wallPaper wallPaper, String theme, DialogInterface dialogInterface, int i) {
        runLinkRequest(intentAccount, username, group, sticker, botUser, botChat, message, hasUrl, messageId, channelId, game, auth, lang, unsupportedUrl, code, wallPaper, theme, 1);
    }

    public /* synthetic */ void lambda$runLinkRequest$16$LaunchActivity(final int intentAccount, final AlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.Updates updates = (TLRPC.Updates) response;
            MessagesController.getInstance(intentAccount).processUpdates(updates, false);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$hwhFCS056kGoViCUA_0uaoeEqpY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$15$LaunchActivity(progressDialog, error, response, intentAccount);
            }
        });
    }

    public /* synthetic */ void lambda$null$15$LaunchActivity(AlertDialog progressDialog, TLRPC.TL_error error, TLObject response, int intentAccount) {
        if (!isFinishing()) {
            try {
                progressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
            if (error == null) {
                if (this.actionBarLayout != null) {
                    TLRPC.Updates updates = (TLRPC.Updates) response;
                    if (!updates.chats.isEmpty()) {
                        TLRPC.Chat chat = updates.chats.get(0);
                        chat.left = false;
                        chat.kicked = false;
                        MessagesController.getInstance(intentAccount).putUsers(updates.users, false);
                        MessagesController.getInstance(intentAccount).putChats(updates.chats, false);
                        Bundle args = new Bundle();
                        args.putInt("chat_id", chat.id);
                        if (!mainFragmentsStack.isEmpty()) {
                            if (!MessagesController.getInstance(intentAccount).checkCanOpenChat(args, mainFragmentsStack.get(r5.size() - 1))) {
                                return;
                            }
                        }
                        ChatActivity fragment = new ChatActivity(args);
                        NotificationCenter.getInstance(intentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
                        this.actionBarLayout.presentFragment(fragment, false, true, true, false);
                        return;
                    }
                    return;
                }
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            if (error.text.startsWith("FLOOD_WAIT")) {
                builder.setMessage(LocaleController.getString("FloodWait", R.string.FloodWait));
            } else if (error.text.equals("USERS_TOO_MUCH")) {
                builder.setMessage(LocaleController.getString("JoinToGroupErrorFull", R.string.JoinToGroupErrorFull));
            } else {
                builder.setMessage(LocaleController.getString("JoinToGroupErrorNotExist", R.string.JoinToGroupErrorNotExist));
            }
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            showAlertDialog(builder);
        }
    }

    public /* synthetic */ void lambda$runLinkRequest$17$LaunchActivity(boolean hasUrl, int intentAccount, String message, DialogsActivity fragment13, ArrayList dids, CharSequence m, boolean param) {
        long did = ((Long) dids.get(0)).longValue();
        Bundle args13 = new Bundle();
        args13.putBoolean("scrollToTopOnResume", true);
        args13.putBoolean("hasUrl", hasUrl);
        int lower_part = (int) did;
        int high_id = (int) (did >> 32);
        if (lower_part != 0) {
            if (lower_part > 0) {
                args13.putInt("user_id", lower_part);
            } else if (lower_part < 0) {
                args13.putInt("chat_id", -lower_part);
            }
        } else {
            args13.putInt("enc_id", high_id);
        }
        if (MessagesController.getInstance(intentAccount).checkCanOpenChat(args13, fragment13)) {
            NotificationCenter.getInstance(intentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
            MediaDataController.getInstance(intentAccount).saveDraft(did, message, null, null, false);
            this.actionBarLayout.presentFragment(new ChatActivity(args13), true, false, true, false);
        }
    }

    public /* synthetic */ void lambda$runLinkRequest$21$LaunchActivity(int[] requestId, final int intentAccount, final AlertDialog progressDialog, final TLRPC.TL_account_getAuthorizationForm req, final String payload, final String nonce, final String callbackUrl, TLObject response, final TLRPC.TL_error error) {
        final TLRPC.TL_account_authorizationForm authorizationForm = (TLRPC.TL_account_authorizationForm) response;
        if (authorizationForm != null) {
            TLRPC.TL_account_getPassword req2 = new TLRPC.TL_account_getPassword();
            requestId[0] = ConnectionsManager.getInstance(intentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$MHb6kMnykWvWAcGfDxok9VOG-Ek
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$19$LaunchActivity(progressDialog, intentAccount, authorizationForm, req, payload, nonce, callbackUrl, tLObject, tL_error);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$i2eLqQbTy8vuInfTIDpjQvLho1w
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$20$LaunchActivity(progressDialog, error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$19$LaunchActivity(final AlertDialog progressDialog, final int intentAccount, final TLRPC.TL_account_authorizationForm authorizationForm, final TLRPC.TL_account_getAuthorizationForm req, final String payload, final String nonce, final String callbackUrl, final TLObject response1, TLRPC.TL_error error1) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$G5-xsszWRHS-0__vcYUxO2IJMNo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$18$LaunchActivity(progressDialog, response1, intentAccount, authorizationForm, req, payload, nonce, callbackUrl);
            }
        });
    }

    public /* synthetic */ void lambda$null$18$LaunchActivity(AlertDialog progressDialog, TLObject response1, int intentAccount, TLRPC.TL_account_authorizationForm authorizationForm, TLRPC.TL_account_getAuthorizationForm req, String payload, String nonce, String callbackUrl) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (response1 != null) {
            TLRPC.TL_account_password accountPassword = (TLRPC.TL_account_password) response1;
            MessagesController.getInstance(intentAccount).putUsers(authorizationForm.users, false);
            lambda$runLinkRequest$26$LaunchActivity(new PassportActivity(5, req.bot_id, req.scope, req.public_key, payload, nonce, callbackUrl, authorizationForm, accountPassword));
        }
    }

    public /* synthetic */ void lambda$null$20$LaunchActivity(AlertDialog progressDialog, TLRPC.TL_error error) {
        try {
            progressDialog.dismiss();
            if ("APP_VERSION_OUTDATED".equals(error.text)) {
                AlertsCreator.showUpdateAppAlert(this, LocaleController.getString("UpdateAppAlert", R.string.UpdateAppAlert), true);
            } else {
                showAlertDialog(AlertsCreator.createSimpleAlert(this, LocaleController.getString("ErrorOccurred", R.string.ErrorOccurred) + ShellAdbUtils.COMMAND_LINE_END + error.text));
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$runLinkRequest$23$LaunchActivity(final AlertDialog progressDialog, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$CrhUP0J0Tz-hXnuYkC2Mf1pxVnA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$22$LaunchActivity(progressDialog, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$22$LaunchActivity(AlertDialog progressDialog, TLObject response) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (response instanceof TLRPC.TL_help_deepLinkInfo) {
            TLRPC.TL_help_deepLinkInfo res = (TLRPC.TL_help_deepLinkInfo) response;
            AlertsCreator.showUpdateAppAlert(this, res.message, res.update_app);
        }
    }

    public /* synthetic */ void lambda$runLinkRequest$25$LaunchActivity(final AlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$RRhNZFLA2IhMaq2SGXJDDhYDgMI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$24$LaunchActivity(progressDialog, response, error);
            }
        });
    }

    public /* synthetic */ void lambda$null$24$LaunchActivity(AlertDialog progressDialog, TLObject response, TLRPC.TL_error error) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (response instanceof TLRPC.TL_langPackLanguage) {
            TLRPC.TL_langPackLanguage res = (TLRPC.TL_langPackLanguage) response;
            showAlertDialog(AlertsCreator.createLanguageAlert(this, res));
        } else if (error != null) {
            if ("LANG_CODE_NOT_SUPPORTED".equals(error.text)) {
                showAlertDialog(AlertsCreator.createSimpleAlert(this, LocaleController.getString("LanguageUnsupportedError", R.string.LanguageUnsupportedError)));
                return;
            }
            showAlertDialog(AlertsCreator.createSimpleAlert(this, LocaleController.getString("ErrorOccurred", R.string.ErrorOccurred) + ShellAdbUtils.COMMAND_LINE_END + error.text));
        }
    }

    public /* synthetic */ void lambda$runLinkRequest$28$LaunchActivity(final AlertDialog progressDialog, final TLRPC.TL_wallPaper wallPaper, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$6ZtEH0j7wiEIp95EC0cKeGegrRs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$27$LaunchActivity(progressDialog, response, wallPaper, error);
            }
        });
    }

    public /* synthetic */ void lambda$null$27$LaunchActivity(AlertDialog alertDialog, TLObject tLObject, TLRPC.TL_wallPaper tL_wallPaper, TLRPC.TL_error tL_error) {
        Object obj;
        try {
            alertDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (tLObject instanceof TLRPC.TL_wallPaper) {
            TLRPC.TL_wallPaper tL_wallPaper2 = (TLRPC.TL_wallPaper) tLObject;
            if (tL_wallPaper2.pattern) {
                WallpapersListActivity.ColorWallpaper colorWallpaper = new WallpapersListActivity.ColorWallpaper(-1L, tL_wallPaper.settings.background_color, tL_wallPaper2.id, tL_wallPaper.settings.intensity / 100.0f, tL_wallPaper.settings.motion, null);
                colorWallpaper.pattern = tL_wallPaper2;
                obj = colorWallpaper;
            } else {
                obj = tL_wallPaper2;
            }
            WallpaperActivity wallpaperActivity = new WallpaperActivity(obj, null);
            wallpaperActivity.setInitialModes(tL_wallPaper.settings.blur, tL_wallPaper.settings.motion);
            lambda$runLinkRequest$26$LaunchActivity(wallpaperActivity);
            return;
        }
        showAlertDialog(AlertsCreator.createSimpleAlert(this, LocaleController.getString("ErrorOccurred", R.string.ErrorOccurred) + ShellAdbUtils.COMMAND_LINE_END + tL_error.text));
    }

    public /* synthetic */ void lambda$runLinkRequest$29$LaunchActivity() {
        this.loadingThemeFileName = null;
        this.loadingThemeWallpaperName = null;
        this.loadingThemeInfo = null;
        this.loadingThemeProgressDialog = null;
        this.loadingTheme = null;
    }

    public /* synthetic */ void lambda$runLinkRequest$31$LaunchActivity(final AlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$XVAbGKerptt3tWHyNcjSYlSS6eo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$30$LaunchActivity(response, progressDialog, error);
            }
        });
    }

    public /* synthetic */ void lambda$null$30$LaunchActivity(TLObject response, AlertDialog progressDialog, TLRPC.TL_error error) {
        int notFound = 2;
        if (response instanceof TLRPC.TL_theme) {
            TLRPC.TL_theme t = (TLRPC.TL_theme) response;
            if (t.document != null) {
                this.loadingTheme = t;
                this.loadingThemeFileName = FileLoader.getAttachFileName(t.document);
                this.loadingThemeProgressDialog = progressDialog;
                FileLoader.getInstance(this.currentAccount).loadFile(this.loadingTheme.document, t, 1, 1);
                notFound = 0;
            } else {
                notFound = 1;
            }
        } else if (error != null && "THEME_FORMAT_INVALID".equals(error.text)) {
            notFound = 1;
        }
        if (notFound != 0) {
            try {
                progressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
            if (notFound == 1) {
                showAlertDialog(AlertsCreator.createSimpleAlert(this, LocaleController.getString("Theme", R.string.Theme), LocaleController.getString("ThemeNotSupported", R.string.ThemeNotSupported)));
            } else {
                showAlertDialog(AlertsCreator.createSimpleAlert(this, LocaleController.getString("Theme", R.string.Theme), LocaleController.getString("ThemeNotFound", R.string.ThemeNotFound)));
            }
        }
    }

    public /* synthetic */ void lambda$runLinkRequest$34$LaunchActivity(final Bundle args, Integer channelId, int[] requestId, final AlertDialog progressDialog, final BaseFragment lastFragment, final int intentAccount) {
        if (!this.actionBarLayout.presentFragment(new ChatActivity(args))) {
            TLRPC.TL_channels_getChannels req = new TLRPC.TL_channels_getChannels();
            TLRPC.TL_inputChannel inputChannel = new TLRPC.TL_inputChannel();
            inputChannel.channel_id = channelId.intValue();
            req.id.add(inputChannel);
            requestId[0] = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$ZsjSyWzcoew81adQYLRmDjyIRX4
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$33$LaunchActivity(progressDialog, lastFragment, intentAccount, args, tLObject, tL_error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$33$LaunchActivity(final AlertDialog progressDialog, final BaseFragment lastFragment, final int intentAccount, final Bundle args, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$L1mYgNVeqZENATR750IzStLb3rs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$32$LaunchActivity(progressDialog, response, lastFragment, intentAccount, args);
            }
        });
    }

    public /* synthetic */ void lambda$null$32$LaunchActivity(AlertDialog progressDialog, TLObject response, BaseFragment lastFragment, int intentAccount, Bundle args) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        boolean notFound = true;
        if (response instanceof TLRPC.TL_messages_chats) {
            TLRPC.TL_messages_chats res = (TLRPC.TL_messages_chats) response;
            if (!res.chats.isEmpty()) {
                notFound = false;
                MessagesController.getInstance(this.currentAccount).putChats(res.chats, false);
                res.chats.get(0);
                if (lastFragment == null || MessagesController.getInstance(intentAccount).checkCanOpenChat(args, lastFragment)) {
                    this.actionBarLayout.presentFragment(new ChatActivity(args));
                }
            }
        }
        if (notFound) {
            showAlertDialog(AlertsCreator.createSimpleAlert(this, LocaleController.getString("LinkNotFound", R.string.LinkNotFound)));
        }
    }

    static /* synthetic */ void lambda$runLinkRequest$35(int intentAccount, int[] requestId, Runnable cancelRunnableFinal, DialogInterface dialog) {
        ConnectionsManager.getInstance(intentAccount).cancelRequest(requestId[0], true);
        if (cancelRunnableFinal != null) {
            cancelRunnableFinal.run();
        }
    }

    public void checkAppUpdate(final boolean isClick) {
        if (isClick) {
            showCheckUpdateDialog();
        }
        AppUpdater.getInstance(this.currentAccount).checkAppUpdate(new AppUpdater.OnForceUpdateCallback() { // from class: im.uwrkaxlmjj.ui.LaunchActivity.4
            @Override // im.uwrkaxlmjj.ui.utils.AppUpdater.OnForceUpdateCallback
            public void onForce(TLRPC.TL_help_appUpdate res) {
                LaunchActivity.this.dismissCheckUpdateDialog();
                if (LaunchActivity.this.updateAppAlertDialog != null && LaunchActivity.this.updateAppAlertDialog.isShowing()) {
                    return;
                }
                LaunchActivity launchActivity = LaunchActivity.this;
                LaunchActivity launchActivity2 = LaunchActivity.this;
                launchActivity.updateAppAlertDialog = new UpdateAppAlertDialog(launchActivity2, res, launchActivity2.currentAccount);
                LaunchActivity.this.updateAppAlertDialog.show();
            }

            @Override // im.uwrkaxlmjj.ui.utils.AppUpdater.OnForceUpdateCallback
            public void onNormal(TLRPC.TL_help_appUpdate res) {
                LaunchActivity.this.dismissCheckUpdateDialog();
                if (LaunchActivity.this.updateAppAlertDialog != null && LaunchActivity.this.updateAppAlertDialog.isShowing()) {
                    return;
                }
                LaunchActivity launchActivity = LaunchActivity.this;
                LaunchActivity launchActivity2 = LaunchActivity.this;
                launchActivity.updateAppAlertDialog = new UpdateAppAlertDialog(launchActivity2, res, launchActivity2.currentAccount);
                LaunchActivity.this.updateAppAlertDialog.show();
            }

            @Override // im.uwrkaxlmjj.ui.utils.AppUpdater.OnForceUpdateCallback
            public void onNoUpdate() {
                LaunchActivity.this.dismissCheckUpdateDialog();
                LaunchActivity.this.dismissUpdateAppAlertDialog();
                if (isClick) {
                    ToastUtils.show(R.string.NoUpdate);
                }
            }
        }, isClick);
    }

    private void showCheckUpdateDialog() {
        dismissCheckUpdateDialog();
        AlertDialog alertDialog = new AlertDialog(this, 3);
        this.checkUpdateDialog = alertDialog;
        alertDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$siOv8VsYIRK8E3xHmm6Cw2NRkSI
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$showCheckUpdateDialog$36$LaunchActivity(dialogInterface);
            }
        });
        this.checkUpdateDialog.show();
    }

    public /* synthetic */ void lambda$showCheckUpdateDialog$36$LaunchActivity(DialogInterface dialog) {
        AppUpdater.getInstance(this.currentAccount).cancel();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void dismissCheckUpdateDialog() {
        AlertDialog alertDialog = this.checkUpdateDialog;
        if (alertDialog != null) {
            alertDialog.dismiss();
            this.checkUpdateDialog = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void dismissUpdateAppAlertDialog() {
        UpdateAppAlertDialog updateAppAlertDialog = this.updateAppAlertDialog;
        if (updateAppAlertDialog != null) {
            updateAppAlertDialog.dismiss();
            this.updateAppAlertDialog = null;
        }
    }

    public AlertDialog showAlertDialog(AlertDialog.Builder builder) {
        return showAlertDialog(builder.show());
    }

    public AlertDialog showAlertDialog(AlertDialog dialog) {
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            this.visibleDialog = dialog;
            dialog.setCanceledOnTouchOutside(true);
            this.visibleDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.LaunchActivity.5
                @Override // android.content.DialogInterface.OnDismissListener
                public void onDismiss(DialogInterface dialog2) {
                    if (LaunchActivity.this.visibleDialog != null) {
                        if (LaunchActivity.this.visibleDialog != LaunchActivity.this.localeDialog) {
                            if (LaunchActivity.this.visibleDialog == LaunchActivity.this.proxyErrorDialog) {
                                MessagesController.getGlobalMainSettings();
                                SharedPreferences.Editor editor = MessagesController.getGlobalMainSettings().edit();
                                editor.putBoolean("proxy_enabled", false);
                                editor.putBoolean("proxy_enabled_calls", false);
                                editor.commit();
                                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.proxySettingsChanged);
                                ConnectionsManager.setProxySettings(false, "", 1080, "", "", "");
                                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged, new Object[0]);
                                LaunchActivity.this.proxyErrorDialog = null;
                            }
                        } else {
                            try {
                                String shorname = LocaleController.getInstance().getCurrentLocaleInfo().shortName;
                                ToastUtils.show((CharSequence) LaunchActivity.this.getStringForLanguageAlert(shorname.equals("en") ? LaunchActivity.this.englishLocaleStrings : LaunchActivity.this.systemLocaleStrings, "ChangeLanguageLater", R.string.ChangeLanguageLater));
                            } catch (Exception e2) {
                                FileLog.e(e2);
                            }
                            LaunchActivity.this.localeDialog = null;
                        }
                    }
                    LaunchActivity.this.visibleDialog = null;
                }
            });
            return this.visibleDialog;
        } catch (Exception e2) {
            FileLog.e(e2);
            return null;
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent, true, false, false);
    }

    @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
    public void didSelectDialogs(DialogsActivity dialogsFragment, ArrayList<Long> dids, CharSequence message, boolean param) {
        int attachesCount;
        long did;
        int i;
        final long did2 = dids.get(0).longValue();
        int lower_part = (int) did2;
        int high_id = (int) (did2 >> 32);
        ArrayList<TLRPC.User> arrayList = this.contactsToSend;
        int attachesCount2 = arrayList != null ? 0 + arrayList.size() : 0;
        if (this.videoPath != null) {
            attachesCount2++;
        }
        ArrayList<SendMessagesHelper.SendingMediaInfo> arrayList2 = this.photoPathsArray;
        if (arrayList2 != null) {
            attachesCount2 += arrayList2.size();
        }
        ArrayList<String> arrayList3 = this.documentsPathsArray;
        if (arrayList3 != null) {
            attachesCount2 += arrayList3.size();
        }
        ArrayList<Uri> arrayList4 = this.documentsUrisArray;
        if (arrayList4 != null) {
            attachesCount2 += arrayList4.size();
        }
        if (this.videoPath == null && this.photoPathsArray == null && this.documentsPathsArray == null && this.documentsUrisArray == null && this.sendingText != null) {
            attachesCount = attachesCount2 + 1;
        } else {
            attachesCount = attachesCount2;
        }
        if (AlertsCreator.checkSlowMode(this, this.currentAccount, did2, attachesCount > 1)) {
            return;
        }
        Bundle args = new Bundle();
        final int account = dialogsFragment != null ? dialogsFragment.getCurrentAccount() : this.currentAccount;
        args.putBoolean("scrollToTopOnResume", true);
        if (!AndroidUtilities.isTablet()) {
            NotificationCenter.getInstance(account).postNotificationName(NotificationCenter.closeChats, new Object[0]);
        }
        if (lower_part != 0) {
            if (lower_part > 0) {
                args.putInt("user_id", lower_part);
            } else if (lower_part < 0) {
                args.putInt("chat_id", -lower_part);
            }
        } else {
            args.putInt("enc_id", high_id);
        }
        if (!MessagesController.getInstance(account).checkCanOpenChat(args, dialogsFragment)) {
            return;
        }
        final ChatActivity fragment = new ChatActivity(args);
        ArrayList<TLRPC.User> arrayList5 = this.contactsToSend;
        if (arrayList5 != null && arrayList5.size() == 1) {
            if (this.contactsToSend.size() == 1) {
                PhonebookShareActivity contactFragment = new PhonebookShareActivity(null, this.contactsToSendUri, null, null);
                contactFragment.setDelegate(new PhoneBookSelectActivity.PhoneBookSelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$7i-cpJDkg6_9ioUnW6R_xYphhMM
                    @Override // im.uwrkaxlmjj.ui.PhoneBookSelectActivity.PhoneBookSelectActivityDelegate
                    public final void didSelectContact(TLRPC.User user, boolean z, int i2) {
                        this.f$0.lambda$didSelectDialogs$37$LaunchActivity(fragment, account, did2, user, z, i2);
                    }
                });
                this.actionBarLayout.presentFragment(contactFragment, dialogsFragment != null, dialogsFragment == null, true, false);
            }
        } else {
            AccountInstance accountInstance = AccountInstance.getInstance(UserConfig.selectedAccount);
            this.actionBarLayout.presentFragment(fragment, dialogsFragment != null, dialogsFragment == null, true, false);
            String str = this.videoPath;
            if (str != null) {
                fragment.openVideoEditor(str, this.sendingText);
                this.sendingText = null;
            }
            if (this.photoPathsArray != null) {
                String str2 = this.sendingText;
                if (str2 != null && str2.length() <= 1024 && this.photoPathsArray.size() == 1) {
                    this.photoPathsArray.get(0).caption = this.sendingText;
                    this.sendingText = null;
                }
                i = 1;
                did = did2;
                SendMessagesHelper.prepareSendingMedia(accountInstance, this.photoPathsArray, did2, null, null, false, false, null, true, 0, false);
            } else {
                did = did2;
                i = 1;
            }
            if (this.documentsPathsArray != null || this.documentsUrisArray != null) {
                String caption = null;
                String str3 = this.sendingText;
                if (str3 != null && str3.length() <= 1024) {
                    ArrayList<String> arrayList6 = this.documentsPathsArray;
                    int size = arrayList6 != null ? arrayList6.size() : 0;
                    ArrayList<Uri> arrayList7 = this.documentsUrisArray;
                    if (size + (arrayList7 != null ? arrayList7.size() : 0) == i) {
                        caption = this.sendingText;
                        this.sendingText = null;
                    }
                }
                SendMessagesHelper.prepareSendingDocuments(accountInstance, this.documentsPathsArray, this.documentsOriginalPathsArray, this.documentsUrisArray, caption, this.documentsMimeType, did, null, null, null, true, 0);
            }
            String str4 = this.sendingText;
            if (str4 != null) {
                SendMessagesHelper.prepareSendingText(accountInstance, str4, did, true, 0);
            }
            ArrayList<TLRPC.User> arrayList8 = this.contactsToSend;
            if (arrayList8 != null && !arrayList8.isEmpty()) {
                for (int a = 0; a < this.contactsToSend.size(); a++) {
                    TLRPC.User user = this.contactsToSend.get(a);
                    SendMessagesHelper.getInstance(account).sendMessage(user, did, (MessageObject) null, (TLRPC.ReplyMarkup) null, (HashMap<String, String>) null, true, 0);
                }
            }
        }
        this.photoPathsArray = null;
        this.videoPath = null;
        this.sendingText = null;
        this.documentsPathsArray = null;
        this.documentsOriginalPathsArray = null;
        this.contactsToSend = null;
        this.contactsToSendUri = null;
    }

    public /* synthetic */ void lambda$didSelectDialogs$37$LaunchActivity(ChatActivity fragment, int account, long did, TLRPC.User user, boolean notify, int scheduleDate) {
        this.actionBarLayout.presentFragment(fragment, true, false, true, false);
        SendMessagesHelper.getInstance(account).sendMessage(user, did, (MessageObject) null, (TLRPC.ReplyMarkup) null, (HashMap<String, String>) null, notify, scheduleDate);
    }

    private void onFinish() {
        if (this.finished) {
            return;
        }
        this.finished = true;
        Runnable runnable = this.lockRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.lockRunnable = null;
        }
        int i = this.currentAccount;
        if (i != -1) {
            NotificationCenter.getInstance(i).removeObserver(this, NotificationCenter.appDidLogout);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.mainUserInfoChanged);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didUpdateConnectionState);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.needShowAlert);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.wasUnableToFindCurrentLocation);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.openArticle);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.hasNewContactsToImport);
        }
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.needShowAlert);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didSetNewWallpapper);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.suggestedLangpack);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.reloadInterface);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didSetNewTheme);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.needSetDayNightTheme);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.closeOtherAppActivities);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didSetPasscode);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.notificationsCountUpdated);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.receivedAVideoCallRequest);
    }

    /* JADX INFO: renamed from: presentFragment, reason: merged with bridge method [inline-methods] */
    public void lambda$runLinkRequest$26$LaunchActivity(BaseFragment fragment) {
        this.actionBarLayout.presentFragment(fragment);
    }

    public boolean presentFragment(BaseFragment fragment, boolean removeLast, boolean forceWithoutAnimation) {
        return this.actionBarLayout.presentFragment(fragment, removeLast, forceWithoutAnimation, true, false);
    }

    public ActionBarLayout getActionBarLayout() {
        return this.actionBarLayout;
    }

    public ActionBarLayout getLayersActionBarLayout() {
        return this.layersActionBarLayout;
    }

    public ActionBarLayout getRightActionBarLayout() {
        return this.rightActionBarLayout;
    }

    private void parseSechmeOpenAccount(String url) {
        if (TextUtils.isEmpty(url)) {
            return;
        }
        String url2 = url.replace("hchat:openKey=", "").replace("hchat://openKey=", "");
        if (!TextUtils.isEmpty(url2)) {
            String result = url2.replace("%3D", "=");
            byte[] decode = Base64.decode(result, 0);
            String ret = new String(decode);
            String[] split = ret.split("#");
            String pUid = split[0].split("=")[1];
            String hash = split[1].split("=")[1];
            if (ret.contains("Uname")) {
                String uName = split[2].split("=")[1];
                boolean closeLast = true;
                if (getActionBarLayout().fragmentsStack != null && getActionBarLayout().fragmentsStack.size() > 1) {
                    closeLast = false;
                }
                MessagesController.getInstance(UserConfig.selectedAccount).openByUserName(uName, getActionBarLayout().getCurrentFragment(), 1, closeLast);
                return;
            }
            TLRPC.User user = new TLRPC.TL_user();
            try {
                user.id = Integer.valueOf(pUid).intValue();
                user.access_hash = Long.valueOf(hash).longValue();
                getUserInfo(user);
            } catch (NumberFormatException e) {
                FileLog.e("parse qr code err:" + e);
            }
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (SharedConfig.passcodeHash.length() != 0 && SharedConfig.lastPauseTime != 0) {
            SharedConfig.lastPauseTime = 0;
            UserConfig.getInstance(this.currentAccount).saveConfig(false);
        }
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PLAY_SERVICES_REQUEST_CHECK_SETTINGS) {
            LocationController.getInstance(this.currentAccount).startFusedLocationRequest(resultCode == -1);
            return;
        }
        ThemeEditorView editorView = ThemeEditorView.getInstance();
        if (editorView != null) {
            editorView.onActivityResult(requestCode, resultCode, data);
        }
        if (this.actionBarLayout.fragmentsStack.size() != 0) {
            BaseFragment fragment = this.actionBarLayout.fragmentsStack.get(this.actionBarLayout.fragmentsStack.size() - 1);
            fragment.onActivityResultFragment(requestCode, resultCode, data);
        }
        if (AndroidUtilities.isTablet()) {
            if (this.rightActionBarLayout.fragmentsStack.size() != 0) {
                BaseFragment fragment2 = this.rightActionBarLayout.fragmentsStack.get(this.rightActionBarLayout.fragmentsStack.size() - 1);
                fragment2.onActivityResultFragment(requestCode, resultCode, data);
            }
            if (this.layersActionBarLayout.fragmentsStack.size() != 0) {
                BaseFragment fragment3 = this.layersActionBarLayout.fragmentsStack.get(this.layersActionBarLayout.fragmentsStack.size() - 1);
                fragment3.onActivityResultFragment(requestCode, resultCode, data);
            }
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        boolean granted = grantResults.length > 0 && grantResults[0] == 0;
        if (requestCode == 4 || requestCode == 17) {
            if (!granted) {
                showPermissionErrorAlert(LocaleController.getString("PermissionStorage", R.string.PermissionStorage));
            } else {
                ImageLoader.getInstance().checkMediaPaths();
            }
        } else if (requestCode == 5) {
            if (!granted) {
                ContactsController.getInstance(this.currentAccount).forceImportContacts();
            } else {
                showPermissionErrorAlert(LocaleController.getString("PermissionContacts", R.string.PermissionContacts));
                return;
            }
        } else if (requestCode == 3) {
            boolean audioGranted = true;
            boolean cameraGranted = true;
            int size = permissions.length;
            for (int i = 0; i < size; i++) {
                if ("android.permission.RECORD_AUDIO".equals(permissions[i])) {
                    audioGranted = grantResults[i] == 0;
                } else if ("android.permission.CAMERA".equals(permissions[i])) {
                    cameraGranted = grantResults[i] == 0;
                }
            }
            if (!audioGranted) {
                showPermissionErrorAlert(LocaleController.getString("PermissionNoAudio", R.string.PermissionNoAudio));
            } else if (!cameraGranted) {
                showPermissionErrorAlert(LocaleController.getString("PermissionNoCamera", R.string.PermissionNoCamera));
            } else {
                if (SharedConfig.inappCamera) {
                    CameraController.getInstance().initCamera(null);
                    return;
                }
                return;
            }
        } else if (requestCode == 18 || requestCode == 19 || requestCode == 20 || requestCode == 22) {
            if (!granted) {
                showPermissionErrorAlert(LocaleController.getString("PermissionNoCamera", R.string.PermissionNoCamera));
            }
        } else if (requestCode == 2 && granted) {
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.locationPermissionGranted, new Object[0]);
        }
        if (requestCode == 102 && Build.VERSION.SDK_INT < 29) {
            boolean needStartService = true;
            for (int i2 = 0; i2 < permissions.length; i2++) {
                String per = permissions[i2];
                boolean result = grantResults[i2] == 0;
                if (!result && (per == "android.permission.READ_CALL_LOG" || per == "android.permission.WRITE_CALL_LOG")) {
                    needStartService = false;
                    break;
                }
            }
            if (needStartService) {
                if (Build.VERSION.SDK_INT < 26 || Build.VERSION.SDK_INT == 28) {
                    Intent interceptor = new Intent(this, (Class<?>) CallApiBelow26And28Service.class);
                    startService(interceptor);
                } else if (Build.VERSION.SDK_INT == 26 || Build.VERSION.SDK_INT == 27) {
                    Intent intent = new Intent("android.telecom.action.CHANGE_DEFAULT_DIALER");
                    intent.putExtra("android.telecom.extra.CHANGE_DEFAULT_DIALER_PACKAGE_NAME", getApplicationContext().getPackageName());
                    intent.addFlags(C.ENCODING_PCM_MU_LAW);
                    startActivity(intent);
                }
            }
        }
        if (this.actionBarLayout.fragmentsStack.size() != 0) {
            BaseFragment fragment = this.actionBarLayout.fragmentsStack.get(this.actionBarLayout.fragmentsStack.size() - 1);
            fragment.onRequestPermissionsResultFragment(requestCode, permissions, grantResults);
        }
        if (AndroidUtilities.isTablet()) {
            if (this.rightActionBarLayout.fragmentsStack.size() != 0) {
                BaseFragment fragment2 = this.rightActionBarLayout.fragmentsStack.get(this.rightActionBarLayout.fragmentsStack.size() - 1);
                fragment2.onRequestPermissionsResultFragment(requestCode, permissions, grantResults);
            }
            if (this.layersActionBarLayout.fragmentsStack.size() != 0) {
                BaseFragment fragment3 = this.layersActionBarLayout.fragmentsStack.get(this.layersActionBarLayout.fragmentsStack.size() - 1);
                fragment3.onRequestPermissionsResultFragment(requestCode, permissions, grantResults);
            }
        }
    }

    private void showPermissionErrorAlert(String message) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(message);
        builder.setNegativeButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$BVBeJxRnKWqsyajdNngCUoCbVjg
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showPermissionErrorAlert$38$LaunchActivity(dialogInterface, i);
            }
        });
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        builder.show();
    }

    public /* synthetic */ void lambda$showPermissionErrorAlert$38$LaunchActivity(DialogInterface dialog, int which) {
        try {
            Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
            intent.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
            startActivity(intent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onPause() {
        super.onPause();
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("LaunchActivity ---> onPause");
        }
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 4096);
        SharedConfig.lastAppPauseTime = System.currentTimeMillis();
        ApplicationLoader.mainInterfacePaused = true;
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$5CT0ISBADcBURNxIJUwlKabfFc0
            @Override // java.lang.Runnable
            public final void run() {
                LaunchActivity.lambda$onPause$39();
            }
        });
        onPasscodePause();
        this.actionBarLayout.onPause();
        if (AndroidUtilities.isTablet()) {
            this.rightActionBarLayout.onPause();
            this.layersActionBarLayout.onPause();
        }
        PasscodeView passcodeView = this.passcodeView;
        if (passcodeView != null) {
            passcodeView.onPause();
        }
        ConnectionsManager.getInstance(this.currentAccount).setAppPaused(true, false);
        if (PhotoViewer.hasInstance() && PhotoViewer.getInstance().isVisible()) {
            PhotoViewer.getInstance().onPause();
        }
    }

    static /* synthetic */ void lambda$onPause$39() {
        ApplicationLoader.mainInterfacePausedStageQueue = true;
        ApplicationLoader.mainInterfacePausedStageQueueTime = 0L;
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onStart() {
        super.onStart();
        Browser.bindCustomTabsService(this);
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onStop() {
        super.onStop();
        if (!AndroidUtilities.isAppOnForeground(this)) {
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.hideAVideoFloatWindow, 1);
            this.mBytJumpFromBack = (byte) 1;
            clearNotification();
        }
        Browser.unbindCustomTabsService(this);
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onDestroy() {
        if (PhotoViewer.getPipInstance() != null) {
            PhotoViewer.getPipInstance().destroyPhotoViewer();
        }
        if (PhotoViewer.hasInstance()) {
            PhotoViewer.getInstance().destroyPhotoViewer();
        }
        if (ImagePreviewActivity.getPipInstance() != null) {
            ImagePreviewActivity.getPipInstance().destroyPhotoViewer();
        }
        if (ImagePreviewActivity.hasInstance()) {
            ImagePreviewActivity.getInstance().destroyPhotoViewer();
        }
        if (PlayerUtils.getPlayer() != null) {
            PlayerUtils.getPlayer().pause();
            PlayerUtils.getPlayer().destroy();
        }
        if (SecretMediaViewer.hasInstance()) {
            SecretMediaViewer.getInstance().destroyPhotoViewer();
        }
        if (ArticleViewer.hasInstance()) {
            ArticleViewer.getInstance().destroyArticleViewer();
        }
        if (ContentPreviewViewer.hasInstance()) {
            ContentPreviewViewer.getInstance().destroy();
        }
        PipRoundVideoView pipRoundVideoView = PipRoundVideoView.getInstance();
        MediaController.getInstance().setBaseActivity(this, false);
        MediaController.getInstance().setFeedbackView(this.actionBarLayout, false);
        if (pipRoundVideoView != null) {
            pipRoundVideoView.close(false);
        }
        Theme.destroyResources();
        EmbedBottomSheet embedBottomSheet = EmbedBottomSheet.getInstance();
        if (embedBottomSheet != null) {
            embedBottomSheet.destroy();
        }
        ThemeEditorView editorView = ThemeEditorView.getInstance();
        if (editorView != null) {
            editorView.destroy();
        }
        DiscoveryJumpPausedFloatingView.destroy();
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            if (this.onGlobalLayoutListener != null) {
                View view = getWindow().getDecorView().getRootView();
                view.getViewTreeObserver().removeOnGlobalLayoutListener(this.onGlobalLayoutListener);
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        super.onDestroy();
        onFinish();
    }

    private void clearNotification() {
        NotificationManager service = (NotificationManager) getSystemService("notification");
        if (service != null) {
            service.cancelAll();
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    protected void onResume() {
        MessageObject messageObject;
        super.onResume();
        byte b = this.mBytJumpFromBack;
        if (b == 1 || b == 0) {
            clearNotification();
        }
        this.mBytJumpFromBack = (byte) 2;
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 4096);
        MediaController.getInstance().setFeedbackView(this.actionBarLayout, true);
        ApplicationLoader.mainInterfacePaused = false;
        showLanguageAlert(false);
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$c4Rev6abTn9oK6AGNrQXikqph1s
            @Override // java.lang.Runnable
            public final void run() {
                LaunchActivity.lambda$onResume$40();
            }
        });
        checkFreeDiscSpace();
        MediaController.checkGallery();
        onPasscodeResume();
        if (this.passcodeView.getVisibility() != 0) {
            this.actionBarLayout.onResume();
            if (AndroidUtilities.isTablet()) {
                this.rightActionBarLayout.onResume();
                this.layersActionBarLayout.onResume();
            }
        } else {
            this.actionBarLayout.dismissDialogs();
            if (AndroidUtilities.isTablet()) {
                this.rightActionBarLayout.dismissDialogs();
                this.layersActionBarLayout.dismissDialogs();
            }
            this.passcodeView.onResume();
        }
        ConnectionsManager.getInstance(this.currentAccount).setAppPaused(false, false);
        updateCurrentConnectionState(this.currentAccount);
        if (PhotoViewer.hasInstance() && PhotoViewer.getInstance().isVisible()) {
            PhotoViewer.getInstance().onResume();
        }
        PipRoundVideoView pipRoundVideoView = PipRoundVideoView.getInstance();
        if (pipRoundVideoView != null && MediaController.getInstance().isMessagePaused() && (messageObject = MediaController.getInstance().getPlayingMessageObject()) != null) {
            MediaController.getInstance().seekToProgress(messageObject, messageObject.audioProgress);
        }
        if (UserConfig.getInstance(UserConfig.selectedAccount).unacceptedTermsOfService != null) {
            showTosActivity(UserConfig.selectedAccount, UserConfig.getInstance(UserConfig.selectedAccount).unacceptedTermsOfService);
        } else if (AppUpdater.pendingAppUpdate != null) {
            dismissCheckUpdateDialog();
            UpdateAppAlertDialog updateAppAlertDialog = this.updateAppAlertDialog;
            if (updateAppAlertDialog != null && updateAppAlertDialog.isShowing()) {
                return;
            }
            UpdateAppAlertDialog updateAppAlertDialog2 = new UpdateAppAlertDialog(this, AppUpdater.pendingAppUpdate, this.currentAccount);
            this.updateAppAlertDialog = updateAppAlertDialog2;
            updateAppAlertDialog2.show();
        }
        checkAppUpdate(false);
        processVisualCallRequest();
        RingUtils.stopMediaPlayerRing();
        try {
            if (ApplicationLoader.mbytAVideoCallBusy != 1) {
                if (ApplicationLoader.mbytAVideoCallBusy == 2) {
                    startActivity(new Intent(this, (Class<?>) VisualCallActivity.class));
                } else if (ApplicationLoader.mbytAVideoCallBusy == 3 || ApplicationLoader.mbytAVideoCallBusy == 4) {
                    NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.hideAVideoFloatWindow, 0);
                }
            } else {
                startActivity(new Intent(this, (Class<?>) VisualCallReceiveActivity.class));
            }
        } catch (Exception e) {
        }
    }

    static /* synthetic */ void lambda$onResume$40() {
        ApplicationLoader.mainInterfacePausedStageQueue = false;
        ApplicationLoader.mainInterfacePausedStageQueueTime = System.currentTimeMillis();
    }

    private void processVisualCallRequest() {
        final ArrayList<VisualCallRequestParaBean> arrayList = DatabaseInstance.queryVisualCallRequest();
        if (arrayList.size() > 0) {
            this.actionBarLayout.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$g7lCUQbytsnXDSW_WJ8GsaZJM1Q
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processVisualCallRequest$41$LaunchActivity(arrayList);
                }
            }, 500L);
        }
    }

    public /* synthetic */ void lambda$processVisualCallRequest$41$LaunchActivity(ArrayList arrayList) {
        DatabaseInstance.deleteVisualCallRequest();
        VisualCallRequestParaBean paraBean = (VisualCallRequestParaBean) arrayList.get(0);
        Intent actIntent = new Intent(this, (Class<?>) VisualCallReceiveActivity.class);
        actIntent.putExtra("video", paraBean.isVideo());
        actIntent.putExtra(TtmlNode.ATTR_ID, paraBean.getStrId());
        actIntent.putExtra("admin_id", paraBean.getAdmin_id());
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("Launch call ===> processVisualCallRequest admin_id = " + paraBean.getAdmin_id());
        }
        actIntent.putExtra("app_id", paraBean.getApp_id());
        actIntent.putExtra("token", paraBean.getToken());
        List<String> a = Arrays.asList(paraBean.getGslb().split(","));
        actIntent.putStringArrayListExtra("gslb", new ArrayList<>(a));
        actIntent.putExtra("json", paraBean.getJson());
        actIntent.putExtra("from", 1);
        actIntent.addFlags(C.ENCODING_PCM_MU_LAW);
        startActivity(actIntent);
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration newConfig) {
        AndroidUtilities.checkDisplaySize(this, newConfig);
        super.onConfigurationChanged(newConfig);
        checkLayout();
        PipRoundVideoView pipRoundVideoView = PipRoundVideoView.getInstance();
        if (pipRoundVideoView != null) {
            pipRoundVideoView.onConfigurationChanged();
        }
        EmbedBottomSheet embedBottomSheet = EmbedBottomSheet.getInstance();
        if (embedBottomSheet != null) {
            embedBottomSheet.onConfigurationChanged(newConfig);
        }
        PhotoViewer photoViewer = PhotoViewer.getPipInstance();
        if (photoViewer != null) {
            photoViewer.onConfigurationChanged(newConfig);
        }
        ThemeEditorView editorView = ThemeEditorView.getInstance();
        if (editorView != null) {
            editorView.onConfigurationChanged();
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onMultiWindowModeChanged(boolean isInMultiWindowMode) {
        AndroidUtilities.isInMultiwindow = isInMultiWindowMode;
        checkLayout();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, final int account, Object... args) {
        View child;
        if (id == NotificationCenter.appDidLogout) {
            switchToAvailableAccountOrLogout();
            return;
        }
        boolean z = false;
        if (id == NotificationCenter.closeOtherAppActivities) {
            if (args[0] != this) {
                onFinish();
                finish();
                return;
            }
            return;
        }
        if (id == NotificationCenter.didUpdateConnectionState) {
            int state = ConnectionsManager.getInstance(account).getConnectionState();
            if (this.currentConnectionState != state) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("switch to state " + state);
                }
                this.currentConnectionState = state;
                updateCurrentConnectionState(account);
                return;
            }
            return;
        }
        if (id == NotificationCenter.mainUserInfoChanged) {
            this.drawerLayoutAdapter.notifyDataSetChanged();
            return;
        }
        if (id == NotificationCenter.needShowAlert) {
            Integer reason = (Integer) args[0];
            if (reason.intValue() == 3 && this.proxyErrorDialog != null) {
                return;
            }
            if (reason.intValue() == 4) {
                showTosActivity(account, (TLRPC.TL_help_termsOfService) args[1]);
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            if (reason.intValue() != 2 && reason.intValue() != 3) {
                builder.setNegativeButton(LocaleController.getString("MoreInfo", R.string.MoreInfo), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$UhGUN0ZblktJq579b7NdmAhIiXY
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        LaunchActivity.lambda$didReceivedNotification$42(account, dialogInterface, i);
                    }
                });
            }
            if (reason.intValue() == 5) {
                builder.setMessage(LocaleController.getString("NobodyLikesSpam3", R.string.NobodyLikesSpam3));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            } else if (reason.intValue() == 0) {
                builder.setMessage(LocaleController.getString("NobodyLikesSpam1", R.string.NobodyLikesSpam1));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            } else if (reason.intValue() == 1) {
                builder.setMessage(LocaleController.getString("NobodyLikesSpam2", R.string.NobodyLikesSpam2));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            } else if (reason.intValue() == 2) {
                if ("ErrorSendMessageTooFreq".equals((String) args[1])) {
                    builder.setMessage(LocaleController.getString(R.string.ErrorSendMessageTooFreq));
                } else {
                    builder.setMessage((String) args[1]);
                }
                String type = (String) args[2];
                if (type.startsWith("AUTH_KEY_DROP_")) {
                    builder.setPositiveButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                    builder.setNegativeButton(LocaleController.getString("LogOut", R.string.LogOut), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$8gjcjS2IY7Gd2MWRdjREphwIho4
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            this.f$0.lambda$didReceivedNotification$43$LaunchActivity(dialogInterface, i);
                        }
                    });
                } else {
                    builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                }
            } else if (reason.intValue() == 3) {
                builder.setMessage(LocaleController.getString("UseProxyErrorTips", R.string.UseProxyErrorTips));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                this.proxyErrorDialog = showAlertDialog(builder);
                return;
            }
            if (!mainFragmentsStack.isEmpty()) {
                ArrayList<BaseFragment> arrayList = mainFragmentsStack;
                arrayList.get(arrayList.size() - 1).showDialog(builder.create());
                return;
            }
            return;
        }
        if (id == NotificationCenter.wasUnableToFindCurrentLocation) {
            AlertDialog.Builder builder2 = new AlertDialog.Builder(this);
            builder2.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder2.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            builder2.setNegativeButton(LocaleController.getString("ShareYouLocationUnableManually", R.string.ShareYouLocationUnableManually), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$vICS8j8dW_rDSwQ2Y9armTV5guo
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$didReceivedNotification$44$LaunchActivity(dialogInterface, i);
                }
            });
            builder2.setMessage(LocaleController.getString("ShareYouLocationUnable", R.string.ShareYouLocationUnable));
            if (!mainFragmentsStack.isEmpty()) {
                ArrayList<BaseFragment> arrayList2 = mainFragmentsStack;
                arrayList2.get(arrayList2.size() - 1).showDialog(builder2.create());
                return;
            }
            return;
        }
        if (id == NotificationCenter.didSetNewWallpapper) {
            RecyclerListView recyclerListView = this.sideMenu;
            if (recyclerListView != null && (child = recyclerListView.getChildAt(0)) != null) {
                child.invalidate();
                return;
            }
            return;
        }
        if (id == NotificationCenter.didSetPasscode) {
            if (SharedConfig.passcodeHash.length() > 0 && !SharedConfig.allowScreenCapture) {
                try {
                    getWindow().setFlags(8192, 8192);
                    return;
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            }
            if (!MediaController.getInstance().hasFlagSecureFragment()) {
                try {
                    getWindow().clearFlags(8192);
                    return;
                } catch (Exception e2) {
                    FileLog.e(e2);
                    return;
                }
            }
            return;
        }
        if (id == NotificationCenter.reloadInterface) {
            if (mainFragmentsStack.size() > 1) {
                ArrayList<BaseFragment> arrayList3 = mainFragmentsStack;
                if (arrayList3.get(arrayList3.size() - 1) instanceof SettingsActivity) {
                    z = true;
                }
            }
            boolean last = z;
            rebuildAllFragments(last);
            return;
        }
        if (id == NotificationCenter.suggestedLangpack) {
            showLanguageAlert(false);
            return;
        }
        if (id == NotificationCenter.openArticle) {
            if (mainFragmentsStack.isEmpty()) {
                return;
            }
            ArticleViewer articleViewer = ArticleViewer.getInstance();
            ArrayList<BaseFragment> arrayList4 = mainFragmentsStack;
            articleViewer.setParentActivity(this, arrayList4.get(arrayList4.size() - 1));
            ArticleViewer.getInstance().open((TLRPC.TL_webPage) args[0], (String) args[1]);
            return;
        }
        if (id == NotificationCenter.hasNewContactsToImport) {
            ActionBarLayout actionBarLayout = this.actionBarLayout;
            if (actionBarLayout == null || actionBarLayout.fragmentsStack.isEmpty()) {
                return;
            }
            ((Integer) args[0]).intValue();
            final HashMap<String, ContactsController.Contact> contactHashMap = (HashMap) args[1];
            final boolean first = ((Boolean) args[2]).booleanValue();
            final boolean schedule = ((Boolean) args[3]).booleanValue();
            BaseFragment fragment = this.actionBarLayout.fragmentsStack.get(this.actionBarLayout.fragmentsStack.size() - 1);
            AlertDialog.Builder builder3 = new AlertDialog.Builder(this);
            builder3.setTitle(LocaleController.getString("UpdateContactsTitle", R.string.UpdateContactsTitle));
            builder3.setMessage(LocaleController.getString("UpdateContactsMessage", R.string.UpdateContactsMessage));
            builder3.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$ImgBzVIsvbh2ZLEo2iFyIs9hCsk
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    ContactsController.getInstance(account).syncPhoneBookByAlert(contactHashMap, first, schedule, false);
                }
            });
            builder3.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$KJ14puLyo7xmx0HQnd-B6GeCVfE
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    ContactsController.getInstance(account).syncPhoneBookByAlert(contactHashMap, first, schedule, true);
                }
            });
            builder3.setOnBackButtonListener(new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$lb2Ezl_QsaXeA_9eGiCYnjqZYMY
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    ContactsController.getInstance(account).syncPhoneBookByAlert(contactHashMap, first, schedule, true);
                }
            });
            AlertDialog dialog = builder3.create();
            fragment.showDialog(dialog);
            dialog.setCanceledOnTouchOutside(false);
            return;
        }
        if (id == NotificationCenter.didSetNewTheme) {
            Boolean nightTheme = (Boolean) args[0];
            if (!nightTheme.booleanValue()) {
                RecyclerListView recyclerListView2 = this.sideMenu;
                if (recyclerListView2 != null) {
                    recyclerListView2.setBackgroundColor(Theme.getColor(Theme.key_chats_menuBackground));
                    this.sideMenu.setGlowColor(Theme.getColor(Theme.key_chats_menuBackground));
                    this.sideMenu.setListSelectorColor(Theme.getColor(Theme.key_listSelector));
                    this.sideMenu.getAdapter().notifyDataSetChanged();
                }
                if (Build.VERSION.SDK_INT >= 21) {
                    try {
                        setTaskDescription(new ActivityManager.TaskDescription((String) null, (Bitmap) null, Theme.getColor(Theme.key_actionBarDefault) | (-16777216)));
                    } catch (Exception e3) {
                    }
                }
            }
            this.drawerLayoutContainer.setBehindKeyboardColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            return;
        }
        if (id == NotificationCenter.needSetDayNightTheme) {
            Theme.ThemeInfo theme = (Theme.ThemeInfo) args[0];
            boolean nigthTheme = ((Boolean) args[1]).booleanValue();
            this.actionBarLayout.animateThemedValues(theme, nigthTheme);
            if (AndroidUtilities.isTablet()) {
                this.layersActionBarLayout.animateThemedValues(theme, nigthTheme);
                this.rightActionBarLayout.animateThemedValues(theme, nigthTheme);
                return;
            }
            return;
        }
        if (id == NotificationCenter.notificationsCountUpdated) {
            RecyclerListView recyclerListView3 = this.sideMenu;
            if (recyclerListView3 != null) {
                Integer accountNum = (Integer) args[0];
                int count = recyclerListView3.getChildCount();
                for (int a = 0; a < count; a++) {
                    View child2 = this.sideMenu.getChildAt(a);
                    if ((child2 instanceof DrawerUserCell) && ((DrawerUserCell) child2).getAccountNumber() == accountNum.intValue()) {
                        child2.invalidate();
                        return;
                    }
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.needShowPlayServicesAlert) {
            try {
                Status status = (Status) args[0];
                status.startResolutionForResult(this, PLAY_SERVICES_REQUEST_CHECK_SETTINGS);
                return;
            } catch (Throwable th) {
                return;
            }
        }
        if (id == NotificationCenter.fileDidLoad) {
            String str = this.loadingThemeFileName;
            if (str != null) {
                if (str.equals((String) args[0])) {
                    this.loadingThemeFileName = null;
                    File locFile = new File(ApplicationLoader.getFilesDirFixed(), "remote" + this.loadingTheme.id + ".attheme");
                    final Theme.ThemeInfo themeInfo = Theme.fillThemeValues(locFile, this.loadingTheme.title, this.loadingTheme);
                    if (themeInfo != null) {
                        if (themeInfo.pathToWallpaper != null) {
                            File file = new File(themeInfo.pathToWallpaper);
                            if (!file.exists()) {
                                TLRPC.TL_account_getWallPaper req = new TLRPC.TL_account_getWallPaper();
                                TLRPC.TL_inputWallPaperSlug inputWallPaperSlug = new TLRPC.TL_inputWallPaperSlug();
                                inputWallPaperSlug.slug = themeInfo.slug;
                                req.wallpaper = inputWallPaperSlug;
                                ConnectionsManager.getInstance(themeInfo.account).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$rEeCoQpmsp5Ct9psfsBL2Nfh1OQ
                                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                        this.f$0.lambda$didReceivedNotification$49$LaunchActivity(themeInfo, tLObject, tL_error);
                                    }
                                });
                                return;
                            }
                        }
                        Theme.ThemeInfo finalThemeInfo = Theme.applyThemeFile(locFile, this.loadingTheme.title, this.loadingTheme, true);
                        if (finalThemeInfo != null) {
                            lambda$runLinkRequest$26$LaunchActivity(new ThemePreviewActivity(finalThemeInfo, true, 0, false));
                        }
                    }
                    onThemeLoadFinish();
                    return;
                }
                return;
            }
            String str2 = this.loadingThemeWallpaperName;
            if (str2 != null && str2.equals((String) args[0])) {
                this.loadingThemeWallpaperName = null;
                final File file2 = (File) args[1];
                Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$2EpOD20AjwqHR7IlRqB1thTHHS4
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$didReceivedNotification$51$LaunchActivity(file2);
                    }
                });
                return;
            }
            return;
        }
        if (id == NotificationCenter.fileDidFailToLoad) {
            String path = (String) args[0];
            if (path.equals(this.loadingThemeFileName) || path.equals(this.loadingThemeWallpaperName)) {
                onThemeLoadFinish();
                return;
            }
            return;
        }
        if (id == NotificationCenter.receivedAVideoCallRequest) {
            TLRPCCall.TL_UpdateMeetCallRequested requested = (TLRPCCall.TL_UpdateMeetCallRequested) args[0];
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("Launch call ===> receive video call , type = " + ((int) ApplicationLoader.mbytAVideoCallBusy));
            }
            if (requested != null) {
                if (!isExistMainActivity(VisualCallReceiveActivity.class)) {
                    Intent intent = new Intent(this, (Class<?>) VisualCallReceiveActivity.class);
                    intent.putExtra("video", false);
                    intent.putExtra(TtmlNode.ATTR_ID, requested.id);
                    intent.putExtra("admin_id", requested.admin_id);
                    intent.putExtra("app_id", requested.appid);
                    intent.putExtra("token", requested.token);
                    intent.putStringArrayListExtra("gslb", requested.gslb);
                    intent.putExtra("json", requested.data.data);
                    startActivity(intent);
                    ApplicationLoader.mbytAVideoCallBusy = (byte) 1;
                    return;
                }
                AVideoCallInterface.IsBusyingNow(requested.id);
                return;
            }
            return;
        }
        if (id == NotificationCenter.folderWebView) {
            createGamePlayingFloatingView();
        }
    }

    static /* synthetic */ void lambda$didReceivedNotification$42(int account, DialogInterface dialogInterface, int i) {
        if (!mainFragmentsStack.isEmpty()) {
            MessagesController messagesController = MessagesController.getInstance(account);
            ArrayList<BaseFragment> arrayList = mainFragmentsStack;
            messagesController.openByUserName("spambot", arrayList.get(arrayList.size() - 1), 1);
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$43$LaunchActivity(DialogInterface dialog, int which) {
        MessagesController.getInstance(this.currentAccount).performLogout(2);
    }

    public /* synthetic */ void lambda$didReceivedNotification$44$LaunchActivity(DialogInterface dialogInterface, int i) {
        if (!mainFragmentsStack.isEmpty() && Build.VERSION.SDK_INT >= 23 && checkSelfPermission(PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION) != 0) {
            requestPermissions(new String[]{PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION, "android.permission.ACCESS_FINE_LOCATION"}, 2);
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$49$LaunchActivity(final Theme.ThemeInfo themeInfo, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$bEGyIS2Ovj5sPOMn_a53_yKaC-4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$48$LaunchActivity(response, themeInfo);
            }
        });
    }

    public /* synthetic */ void lambda$null$48$LaunchActivity(TLObject response, Theme.ThemeInfo themeInfo) {
        if (response instanceof TLRPC.TL_wallPaper) {
            TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) response;
            this.loadingThemeInfo = themeInfo;
            this.loadingThemeWallpaperName = FileLoader.getAttachFileName(wallPaper.document);
            FileLoader.getInstance(themeInfo.account).loadFile(wallPaper.document, wallPaper, 1, 1);
            return;
        }
        onThemeLoadFinish();
    }

    public /* synthetic */ void lambda$didReceivedNotification$51$LaunchActivity(File file) {
        try {
            Bitmap bitmap = ThemesHorizontalListCell.getScaledBitmap(AndroidUtilities.dp(640.0f), AndroidUtilities.dp(360.0f), file.getAbsolutePath(), null, 0);
            if (this.loadingThemeInfo.isBlured) {
                bitmap = Utilities.blurWallpaper(bitmap);
            }
            FileOutputStream stream = new FileOutputStream(this.loadingThemeInfo.pathToWallpaper);
            bitmap.compress(Bitmap.CompressFormat.JPEG, 87, stream);
            stream.close();
        } catch (Throwable e) {
            FileLog.e(e);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$I0T3pLRRpYuIz7mXUKul8grokT0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$50$LaunchActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$50$LaunchActivity() {
        File locFile = new File(ApplicationLoader.getFilesDirFixed(), "remote" + this.loadingTheme.id + ".attheme");
        Theme.ThemeInfo finalThemeInfo = Theme.applyThemeFile(locFile, this.loadingTheme.title, this.loadingTheme, true);
        if (finalThemeInfo != null) {
            lambda$runLinkRequest$26$LaunchActivity(new ThemePreviewActivity(finalThemeInfo, true, 0, false));
        }
        onThemeLoadFinish();
    }

    private boolean isExistMainActivity(Class<?> activity) {
        return ApplicationLoader.mbytAVideoCallBusy == 1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String getStringForLanguageAlert(HashMap<String, String> map, String key, int intKey) {
        String value = map.get(key);
        if (value == null) {
            return LocaleController.getString(key, intKey);
        }
        return value;
    }

    private void onThemeLoadFinish() {
        AlertDialog alertDialog = this.loadingThemeProgressDialog;
        if (alertDialog != null) {
            try {
                alertDialog.dismiss();
            } finally {
                this.loadingThemeProgressDialog = null;
            }
        }
        this.loadingThemeWallpaperName = null;
        this.loadingThemeInfo = null;
        this.loadingThemeFileName = null;
        this.loadingTheme = null;
    }

    private void checkFreeDiscSpace() {
        SharedConfig.checkKeepMedia();
        if (Build.VERSION.SDK_INT >= 26) {
            return;
        }
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$iGu0-LiqcyiStmpk5vUrE-ZkEqk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkFreeDiscSpace$53$LaunchActivity();
            }
        }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
    }

    public /* synthetic */ void lambda$checkFreeDiscSpace$53$LaunchActivity() {
        File path;
        long freeSpace;
        if (!UserConfig.getInstance(this.currentAccount).isClientActivated()) {
            return;
        }
        try {
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            if (Math.abs(preferences.getLong("last_space_check", 0L) - System.currentTimeMillis()) < 259200000 || (path = FileLoader.getDirectory(4)) == null) {
                return;
            }
            StatFs statFs = new StatFs(path.getAbsolutePath());
            if (Build.VERSION.SDK_INT < 18) {
                freeSpace = Math.abs(statFs.getAvailableBlocks() * statFs.getBlockSize());
            } else {
                long freeSpace2 = statFs.getAvailableBlocksLong();
                freeSpace = freeSpace2 * statFs.getBlockSizeLong();
            }
            if (freeSpace < 104857600) {
                preferences.edit().putLong("last_space_check", System.currentTimeMillis()).commit();
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$QzItmm69DwoCU3Tx0dmPqNa2iMI
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$52$LaunchActivity();
                    }
                });
            }
        } catch (Throwable th) {
        }
    }

    public /* synthetic */ void lambda$null$52$LaunchActivity() {
        try {
            AlertsCreator.createFreeSpaceDialog(this).show();
        } catch (Throwable th) {
        }
    }

    private void showLanguageAlertInternal(LocaleController.LocaleInfo systemInfo, LocaleController.LocaleInfo englishInfo, String systemLang) {
        SharedPreferences preferences;
        try {
            this.loadingLocaleDialog = false;
            try {
                boolean firstSystem = systemInfo.builtIn || LocaleController.getInstance().isCurrentLocalLocale();
                AlertDialog.Builder builder = new AlertDialog.Builder(this);
                builder.setTitle(getStringForLanguageAlert(this.systemLocaleStrings, "ChooseYourLanguage", R.string.ChooseYourLanguage));
                builder.setSubtitle(getStringForLanguageAlert(this.englishLocaleStrings, "ChooseYourLanguage", R.string.ChooseYourLanguage));
                LinearLayout linearLayout = new LinearLayout(this);
                linearLayout.setOrientation(1);
                final LanguageCell[] cells = new LanguageCell[2];
                final LocaleController.LocaleInfo[] selectedLanguage = new LocaleController.LocaleInfo[1];
                LocaleController.LocaleInfo[] locales = new LocaleController.LocaleInfo[2];
                String englishName = getStringForLanguageAlert(this.systemLocaleStrings, "English", R.string.English);
                locales[0] = firstSystem ? systemInfo : englishInfo;
                locales[1] = firstSystem ? englishInfo : systemInfo;
                selectedLanguage[0] = firstSystem ? systemInfo : englishInfo;
                int a = 0;
                for (int i = 2; a < i; i = 2) {
                    cells[a] = new LanguageCell(this, true);
                    try {
                        cells[a].setLanguage(locales[a], locales[a] == englishInfo ? englishName : null, true);
                        cells[a].setTag(Integer.valueOf(a));
                        cells[a].setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_dialogButtonSelector), 2));
                        cells[a].setLanguageSelected(a == 0);
                        linearLayout.addView(cells[a], LayoutHelper.createLinear(-1, 50));
                        cells[a].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$izQR-Doe8QsKXijWIEbo-dmcldo
                            @Override // android.view.View.OnClickListener
                            public final void onClick(View view) {
                                LaunchActivity.lambda$showLanguageAlertInternal$54(selectedLanguage, cells, view);
                            }
                        });
                        a++;
                    } catch (Exception e) {
                        e = e;
                        FileLog.e(e);
                    }
                }
                LanguageCell cell = new LanguageCell(this, true);
                cell.setValue(getStringForLanguageAlert(this.systemLocaleStrings, "ChooseYourLanguageOther", R.string.ChooseYourLanguageOther), getStringForLanguageAlert(this.englishLocaleStrings, "ChooseYourLanguageOther", R.string.ChooseYourLanguageOther));
                cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$u_4RggO7elC4_YXo5rFcugQdEqg
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$showLanguageAlertInternal$55$LaunchActivity(view);
                    }
                });
                linearLayout.addView(cell, LayoutHelper.createLinear(-1, 50));
                builder.setView(linearLayout);
                builder.setNegativeButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$xXcH6Pf753PkE3pHHqPEMRkpLG4
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i2) {
                        this.f$0.lambda$showLanguageAlertInternal$56$LaunchActivity(selectedLanguage, dialogInterface, i2);
                    }
                });
                this.localeDialog = showAlertDialog(builder);
                preferences = MessagesController.getGlobalMainSettings();
            } catch (Exception e2) {
                e = e2;
                FileLog.e(e);
            }
            try {
                preferences.edit().putString("language_showed2", systemLang).commit();
            } catch (Exception e3) {
                e = e3;
                FileLog.e(e);
            }
        } catch (Exception e4) {
            e = e4;
        }
    }

    static /* synthetic */ void lambda$showLanguageAlertInternal$54(LocaleController.LocaleInfo[] selectedLanguage, LanguageCell[] cells, View v) {
        Integer tag = (Integer) v.getTag();
        selectedLanguage[0] = ((LanguageCell) v).getCurrentLocale();
        int a1 = 0;
        while (a1 < cells.length) {
            cells[a1].setLanguageSelected(a1 == tag.intValue());
            a1++;
        }
    }

    public /* synthetic */ void lambda$showLanguageAlertInternal$55$LaunchActivity(View v) {
        this.localeDialog = null;
        this.drawerLayoutContainer.closeDrawer(true);
        lambda$runLinkRequest$26$LaunchActivity(new LanguageSelectActivity());
        AlertDialog alertDialog = this.visibleDialog;
        if (alertDialog != null) {
            alertDialog.dismiss();
            this.visibleDialog = null;
        }
    }

    public /* synthetic */ void lambda$showLanguageAlertInternal$56$LaunchActivity(LocaleController.LocaleInfo[] selectedLanguage, DialogInterface dialog, int which) {
        LocaleController.getInstance().applyLanguage(selectedLanguage[0], true, false, this.currentAccount);
        rebuildAllFragments(true);
    }

    private void showLanguageAlert(boolean force) {
        String alias;
        char c;
        try {
            if (!this.loadingLocaleDialog && !ApplicationLoader.mainInterfacePaused) {
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                String showedLang = preferences.getString("language_showed2", "");
                final String systemLang = MessagesController.getInstance(this.currentAccount).suggestedLangCode;
                if (!force && showedLang.equals(systemLang)) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("alert already showed for " + showedLang);
                        return;
                    }
                    return;
                }
                final LocaleController.LocaleInfo[] infos = new LocaleController.LocaleInfo[2];
                String arg = systemLang.contains("-") ? systemLang.split("-")[0] : systemLang;
                if ("in".equals(arg)) {
                    alias = TtmlNode.ATTR_ID;
                } else if ("iw".equals(arg)) {
                    alias = "he";
                } else if ("jw".equals(arg)) {
                    alias = "jv";
                } else {
                    alias = null;
                }
                for (int a = 0; a < LocaleController.getInstance().languages.size(); a++) {
                    LocaleController.LocaleInfo info = LocaleController.getInstance().languages.get(a);
                    if (info.shortName.equals("en")) {
                        infos[0] = info;
                    }
                    if (info.shortName.replace("_", "-").equals(systemLang) || info.shortName.equals(arg) || info.shortName.equals(alias)) {
                        c = 1;
                        infos[1] = info;
                    } else {
                        c = 1;
                    }
                    if (infos[0] != null && infos[c] != null) {
                        break;
                    }
                }
                if (infos[0] != null && infos[1] != null && infos[0] != infos[1]) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("show lang alert for " + infos[0].getKey() + " and " + infos[1].getKey());
                    }
                    this.systemLocaleStrings = null;
                    this.englishLocaleStrings = null;
                    this.loadingLocaleDialog = true;
                    TLRPC.TL_langpack_getStrings req = new TLRPC.TL_langpack_getStrings();
                    req.lang_code = infos[1].getLangCode();
                    req.keys.add("English");
                    req.keys.add("ChooseYourLanguage");
                    req.keys.add("ChooseYourLanguageOther");
                    req.keys.add("ChangeLanguageLater");
                    ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$oBCbYktZko4X7zA7FvH65LUVJFc
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$showLanguageAlert$58$LaunchActivity(infos, systemLang, tLObject, tL_error);
                        }
                    }, 8);
                    TLRPC.TL_langpack_getStrings req2 = new TLRPC.TL_langpack_getStrings();
                    req2.lang_code = infos[0].getLangCode();
                    req2.keys.add("English");
                    req2.keys.add("ChooseYourLanguage");
                    req2.keys.add("ChooseYourLanguageOther");
                    req2.keys.add("ChangeLanguageLater");
                    ConnectionsManager.getInstance(this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$vPkjgetf8fCBhWcnfG_SmRvLsB4
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$showLanguageAlert$60$LaunchActivity(infos, systemLang, tLObject, tL_error);
                        }
                    }, 8);
                }
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$showLanguageAlert$58$LaunchActivity(final LocaleController.LocaleInfo[] infos, final String systemLang, TLObject response, TLRPC.TL_error error) {
        final HashMap<String, String> keys = new HashMap<>();
        if (response != null) {
            TLRPC.Vector vector = (TLRPC.Vector) response;
            for (int a = 0; a < vector.objects.size(); a++) {
                TLRPC.LangPackString string = (TLRPC.LangPackString) vector.objects.get(a);
                keys.put(string.key, string.value);
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$z-ml4JQvqTACUy1jNx365dAR-FE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$57$LaunchActivity(keys, infos, systemLang);
            }
        });
    }

    public /* synthetic */ void lambda$null$57$LaunchActivity(HashMap keys, LocaleController.LocaleInfo[] infos, String systemLang) {
        this.systemLocaleStrings = keys;
        if (this.englishLocaleStrings != null && keys != null) {
            showLanguageAlertInternal(infos[1], infos[0], systemLang);
        }
    }

    public /* synthetic */ void lambda$showLanguageAlert$60$LaunchActivity(final LocaleController.LocaleInfo[] infos, final String systemLang, TLObject response, TLRPC.TL_error error) {
        final HashMap<String, String> keys = new HashMap<>();
        if (response != null) {
            TLRPC.Vector vector = (TLRPC.Vector) response;
            for (int a = 0; a < vector.objects.size(); a++) {
                TLRPC.LangPackString string = (TLRPC.LangPackString) vector.objects.get(a);
                keys.put(string.key, string.value);
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$bjDVWtynPnrAkabVDl-9QyVbV6E
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$59$LaunchActivity(keys, infos, systemLang);
            }
        });
    }

    public /* synthetic */ void lambda$null$59$LaunchActivity(HashMap keys, LocaleController.LocaleInfo[] infos, String systemLang) {
        this.englishLocaleStrings = keys;
        if (keys != null && this.systemLocaleStrings != null) {
            showLanguageAlertInternal(infos[1], infos[0], systemLang);
        }
    }

    private void onPasscodePause() {
        Runnable runnable = this.lockRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.lockRunnable = null;
        }
        if (SharedConfig.passcodeHash.length() != 0) {
            SharedConfig.lastPauseTime = ConnectionsManager.getInstance(this.currentAccount).getCurrentTime();
            this.lockRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.LaunchActivity.6
                @Override // java.lang.Runnable
                public void run() {
                    if (LaunchActivity.this.lockRunnable == this) {
                        if (AndroidUtilities.needShowPasscode(true)) {
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("lock app");
                            }
                            LaunchActivity.this.showPasscodeActivity();
                        } else if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("didn't pass lock check");
                        }
                        LaunchActivity.this.lockRunnable = null;
                    }
                }
            };
            if (SharedConfig.appLocked) {
                AndroidUtilities.runOnUIThread(this.lockRunnable, 1000L);
            } else if (SharedConfig.autoLockIn != 0) {
                AndroidUtilities.runOnUIThread(this.lockRunnable, (((long) SharedConfig.autoLockIn) * 1000) + 1000);
            }
        } else {
            SharedConfig.lastPauseTime = 0;
        }
        SharedConfig.saveConfig();
    }

    private void onPasscodeResume() {
        Runnable runnable = this.lockRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.lockRunnable = null;
        }
        if (AndroidUtilities.needShowPasscode(true)) {
            showPasscodeActivity();
        }
        if (SharedConfig.lastPauseTime != 0) {
            SharedConfig.lastPauseTime = 0;
            SharedConfig.saveConfig();
        }
    }

    private void updateCurrentConnectionState(int account) {
        if (this.actionBarLayout == null) {
            return;
        }
        String title = null;
        int titleId = 0;
        Runnable action = null;
        int connectionState = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
        this.currentConnectionState = connectionState;
        if (connectionState == 2) {
            title = "WaitingForNetwork";
            titleId = R.string.WaitingForNetwork;
        } else if (connectionState == 5) {
            title = "Updating";
            titleId = R.string.Updating;
        } else if (connectionState == 4) {
            title = "ConnectingToProxy";
            titleId = R.string.ConnectingToProxy;
        } else if (connectionState == 1) {
            title = "Connecting";
            titleId = R.string.Connecting;
        }
        int i = this.currentConnectionState;
        if (i == 1 || i == 4) {
            action = new Runnable() { // from class: im.uwrkaxlmjj.ui.LaunchActivity.7
                @Override // java.lang.Runnable
                public void run() {
                    BaseFragment lastFragment = null;
                    if (AndroidUtilities.isTablet()) {
                        if (!LaunchActivity.layerFragmentsStack.isEmpty()) {
                            lastFragment = (BaseFragment) LaunchActivity.layerFragmentsStack.get(LaunchActivity.layerFragmentsStack.size() - 1);
                        }
                    } else if (!LaunchActivity.mainFragmentsStack.isEmpty()) {
                        lastFragment = (BaseFragment) LaunchActivity.mainFragmentsStack.get(LaunchActivity.mainFragmentsStack.size() - 1);
                    }
                    if ((lastFragment instanceof ProxyListActivity) || (lastFragment instanceof ProxySettingsActivity)) {
                    }
                }
            };
        }
        this.actionBarLayout.setTitleOverlayText(title, titleId, action);
    }

    public void hideVisibleActionMode() {
        ActionMode actionMode = this.visibleActionMode;
        if (actionMode == null) {
            return;
        }
        actionMode.finish();
    }

    @Override // androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onSaveInstanceState(Bundle outState) {
        try {
            super.onSaveInstanceState(outState);
            BaseFragment lastFragment = null;
            if (AndroidUtilities.isTablet()) {
                if (!this.layersActionBarLayout.fragmentsStack.isEmpty()) {
                    lastFragment = this.layersActionBarLayout.fragmentsStack.get(this.layersActionBarLayout.fragmentsStack.size() - 1);
                } else if (!this.rightActionBarLayout.fragmentsStack.isEmpty()) {
                    lastFragment = this.rightActionBarLayout.fragmentsStack.get(this.rightActionBarLayout.fragmentsStack.size() - 1);
                } else if (!this.actionBarLayout.fragmentsStack.isEmpty()) {
                    lastFragment = this.actionBarLayout.fragmentsStack.get(this.actionBarLayout.fragmentsStack.size() - 1);
                }
            } else if (!this.actionBarLayout.fragmentsStack.isEmpty()) {
                lastFragment = this.actionBarLayout.fragmentsStack.get(this.actionBarLayout.fragmentsStack.size() - 1);
            }
            if (lastFragment != null) {
                Bundle args = lastFragment.getArguments();
                if ((lastFragment instanceof ChatActivity) && args != null) {
                    outState.putBundle("args", args);
                    outState.putString("fragment", "chat");
                } else if (lastFragment instanceof SettingsActivity) {
                    outState.putString("fragment", "settings");
                } else if ((lastFragment instanceof GroupCreateFinalActivity) && args != null) {
                    outState.putBundle("args", args);
                    outState.putString("fragment", "group");
                } else if (lastFragment instanceof WallpapersListActivity) {
                    outState.putString("fragment", "wallpapers");
                } else if ((lastFragment instanceof ProfileActivity) && ((ProfileActivity) lastFragment).isChat() && args != null) {
                    outState.putBundle("args", args);
                    outState.putString("fragment", "chat_profile");
                } else if ((lastFragment instanceof ChannelCreateActivity) && args != null && args.getInt("step") == 0) {
                    outState.putBundle("args", args);
                    outState.putString("fragment", "channel");
                }
                lastFragment.saveSelfArgs(outState);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        if (this.passcodeView.getVisibility() == 0) {
            finish();
            return;
        }
        if (SecretMediaViewer.hasInstance() && SecretMediaViewer.getInstance().isVisible()) {
            SecretMediaViewer.getInstance().closePhoto(true, false);
            return;
        }
        if (PhotoViewer.hasInstance() && PhotoViewer.getInstance().isVisible()) {
            PhotoViewer.getInstance().closePhoto(true, false);
            return;
        }
        if (ArticleViewer.hasInstance() && ArticleViewer.getInstance().isVisible()) {
            ArticleViewer.getInstance().close(true, false);
            return;
        }
        if (this.drawerLayoutContainer.isDrawerOpened()) {
            this.drawerLayoutContainer.closeDrawer(false);
            return;
        }
        if (AndroidUtilities.isTablet()) {
            if (this.layersActionBarLayout.getVisibility() == 0) {
                this.layersActionBarLayout.onBackPressed();
                return;
            }
            boolean cancel = false;
            if (this.rightActionBarLayout.getVisibility() == 0 && !this.rightActionBarLayout.fragmentsStack.isEmpty()) {
                BaseFragment lastFragment = this.rightActionBarLayout.fragmentsStack.get(this.rightActionBarLayout.fragmentsStack.size() - 1);
                cancel = true ^ lastFragment.onBackPressed();
            }
            if (!cancel) {
                this.actionBarLayout.onBackPressed();
                return;
            }
            return;
        }
        this.actionBarLayout.onBackPressed();
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity, android.content.ComponentCallbacks
    public void onLowMemory() {
        super.onLowMemory();
        this.actionBarLayout.onLowMemory();
        if (AndroidUtilities.isTablet()) {
            this.rightActionBarLayout.onLowMemory();
            this.layersActionBarLayout.onLowMemory();
        }
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public void onActionModeStarted(ActionMode mode) {
        super.onActionModeStarted(mode);
        this.visibleActionMode = mode;
        try {
            Menu menu = mode.getMenu();
            if (menu != null) {
                boolean extended = this.actionBarLayout.extendActionMode(menu);
                if (!extended && AndroidUtilities.isTablet()) {
                    boolean extended2 = this.rightActionBarLayout.extendActionMode(menu);
                    if (!extended2) {
                        this.layersActionBarLayout.extendActionMode(menu);
                    }
                }
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (Build.VERSION.SDK_INT >= 23 && mode.getType() == 1) {
            return;
        }
        this.actionBarLayout.onActionModeStarted(mode);
        if (AndroidUtilities.isTablet()) {
            this.rightActionBarLayout.onActionModeStarted(mode);
            this.layersActionBarLayout.onActionModeStarted(mode);
        }
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public void onActionModeFinished(ActionMode mode) {
        super.onActionModeFinished(mode);
        if (this.visibleActionMode == mode) {
            this.visibleActionMode = null;
        }
        if (Build.VERSION.SDK_INT >= 23 && mode.getType() == 1) {
            return;
        }
        this.actionBarLayout.onActionModeFinished(mode);
        if (AndroidUtilities.isTablet()) {
            this.rightActionBarLayout.onActionModeFinished(mode);
            this.layersActionBarLayout.onActionModeFinished(mode);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.ActionBarLayoutDelegate
    public boolean onPreIme() {
        if (SecretMediaViewer.hasInstance() && SecretMediaViewer.getInstance().isVisible()) {
            SecretMediaViewer.getInstance().closePhoto(true, false);
            return true;
        }
        if (PhotoViewer.hasInstance() && PhotoViewer.getInstance().isVisible()) {
            PhotoViewer.getInstance().closePhoto(true, false);
            return true;
        }
        if (!ArticleViewer.hasInstance() || !ArticleViewer.getInstance().isVisible()) {
            return false;
        }
        ArticleViewer.getInstance().close(true, false);
        return true;
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.core.app.ComponentActivity, android.app.Activity, android.view.Window.Callback
    public boolean dispatchKeyEvent(KeyEvent event) {
        event.getKeyCode();
        if (!mainFragmentsStack.isEmpty() && ((!PhotoViewer.hasInstance() || !PhotoViewer.getInstance().isVisible()) && event.getRepeatCount() == 0 && event.getAction() == 0 && (event.getKeyCode() == 24 || event.getKeyCode() == 25))) {
            ArrayList<BaseFragment> arrayList = mainFragmentsStack;
            BaseFragment fragment = arrayList.get(arrayList.size() - 1);
            if ((fragment instanceof ChatActivity) && ((ChatActivity) fragment).maybePlayVisibleVideo()) {
                return true;
            }
            if (AndroidUtilities.isTablet() && !rightFragmentsStack.isEmpty()) {
                ArrayList<BaseFragment> arrayList2 = rightFragmentsStack;
                BaseFragment fragment2 = arrayList2.get(arrayList2.size() - 1);
                if ((fragment2 instanceof ChatActivity) && ((ChatActivity) fragment2).maybePlayVisibleVideo()) {
                    return true;
                }
            }
        }
        return super.dispatchKeyEvent(event);
    }

    @Override // android.app.Activity, android.view.KeyEvent.Callback
    public boolean onKeyUp(int keyCode, KeyEvent event) {
        if (keyCode == 82 && !SharedConfig.isWaitingForPasscodeEnter) {
            if (PhotoViewer.hasInstance() && PhotoViewer.getInstance().isVisible()) {
                return super.onKeyUp(keyCode, event);
            }
            if (ArticleViewer.hasInstance() && ArticleViewer.getInstance().isVisible()) {
                return super.onKeyUp(keyCode, event);
            }
            if (AndroidUtilities.isTablet()) {
                if (this.layersActionBarLayout.getVisibility() == 0 && !this.layersActionBarLayout.fragmentsStack.isEmpty()) {
                    this.layersActionBarLayout.onKeyUp(keyCode, event);
                } else if (this.rightActionBarLayout.getVisibility() == 0 && !this.rightActionBarLayout.fragmentsStack.isEmpty()) {
                    this.rightActionBarLayout.onKeyUp(keyCode, event);
                } else {
                    this.actionBarLayout.onKeyUp(keyCode, event);
                }
            } else if (this.actionBarLayout.fragmentsStack.size() == 1) {
                if (this.drawerLayoutContainer.isDrawerOpened()) {
                    this.drawerLayoutContainer.closeDrawer(false);
                } else {
                    if (getCurrentFocus() != null) {
                        AndroidUtilities.hideKeyboard(getCurrentFocus());
                    }
                    this.drawerLayoutContainer.openDrawer(false);
                }
            } else {
                this.actionBarLayout.onKeyUp(keyCode, event);
            }
        }
        if (keyCode == 4 && event.getAction() == 1 && ApplicationLoader.mbytLiving == 1 && this.actionBarLayout.fragmentsStack.size() == 1 && (this.actionBarLayout.fragmentsStack.get(0) instanceof IndexActivity)) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage("您正在直播中，确定要退出吗？");
            builder.setNegativeButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$LaunchActivity$bpwbnr6202AqC7-yupSlN5odfbw
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$onKeyUp$61$LaunchActivity(dialogInterface, i);
                }
            });
            builder.setPositiveButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showAlertDialog(builder);
            return true;
        }
        return super.onKeyUp(keyCode, event);
    }

    public /* synthetic */ void lambda$onKeyUp$61$LaunchActivity(DialogInterface dialog, int which) {
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.livefinishnotify, new Object[0]);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$pPCqRdDqAL_EjXpKZZutV5u8300
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.finish();
            }
        }, 1000L);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.ActionBarLayoutDelegate
    public boolean needPresentFragment(BaseFragment fragment, boolean removeLast, boolean forceWithoutAnimation, ActionBarLayout layout) {
        ActionBarLayout actionBarLayout;
        ActionBarLayout actionBarLayout2;
        ActionBarLayout actionBarLayout3;
        if (ArticleViewer.hasInstance() && ArticleViewer.getInstance().isVisible()) {
            ArticleViewer.getInstance().close(false, true);
        }
        if (AndroidUtilities.isTablet()) {
            this.drawerLayoutContainer.setAllowOpenDrawer(false, true);
            if (fragment instanceof IndexActivity) {
                ActionBarLayout actionBarLayout4 = this.actionBarLayout;
                if (layout != actionBarLayout4) {
                    actionBarLayout4.removeAllFragments();
                    this.actionBarLayout.presentFragment(fragment, removeLast, forceWithoutAnimation, false, false);
                    this.layersActionBarLayout.removeAllFragments();
                    this.layersActionBarLayout.setVisibility(8);
                    this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
                    if (!this.tabletFullSize) {
                        this.shadowTabletSide.setVisibility(0);
                        if (this.rightActionBarLayout.fragmentsStack.isEmpty()) {
                            this.backgroundTablet.setVisibility(0);
                        }
                    }
                    return false;
                }
            }
            if ((fragment instanceof ChatActivity) && !((ChatActivity) fragment).isInScheduleMode()) {
                if ((!this.tabletFullSize && layout == this.rightActionBarLayout) || (this.tabletFullSize && layout == this.actionBarLayout)) {
                    boolean result = (this.tabletFullSize && layout == (actionBarLayout3 = this.actionBarLayout) && actionBarLayout3.fragmentsStack.size() == 1) ? false : true;
                    if (!this.layersActionBarLayout.fragmentsStack.isEmpty()) {
                        for (int a = 0; a < this.layersActionBarLayout.fragmentsStack.size() - 1; a = (a - 1) + 1) {
                            ActionBarLayout actionBarLayout5 = this.layersActionBarLayout;
                            actionBarLayout5.removeFragmentFromStack(actionBarLayout5.fragmentsStack.get(0));
                        }
                        this.layersActionBarLayout.closeLastFragment(!forceWithoutAnimation);
                    }
                    if (!result) {
                        this.actionBarLayout.presentFragment(fragment, false, forceWithoutAnimation, false, false);
                    }
                    return result;
                }
                if (!this.tabletFullSize && layout != (actionBarLayout2 = this.rightActionBarLayout)) {
                    actionBarLayout2.setVisibility(0);
                    this.backgroundTablet.setVisibility(8);
                    this.rightActionBarLayout.removeAllFragments();
                    this.rightActionBarLayout.presentFragment(fragment, removeLast, true, false, false);
                    if (!this.layersActionBarLayout.fragmentsStack.isEmpty()) {
                        for (int a2 = 0; a2 < this.layersActionBarLayout.fragmentsStack.size() - 1; a2 = (a2 - 1) + 1) {
                            ActionBarLayout actionBarLayout6 = this.layersActionBarLayout;
                            actionBarLayout6.removeFragmentFromStack(actionBarLayout6.fragmentsStack.get(0));
                        }
                        this.layersActionBarLayout.closeLastFragment(!forceWithoutAnimation);
                    }
                    return false;
                }
                if (this.tabletFullSize && layout != (actionBarLayout = this.actionBarLayout)) {
                    actionBarLayout.presentFragment(fragment, actionBarLayout.fragmentsStack.size() > 1, forceWithoutAnimation, false, false);
                    if (!this.layersActionBarLayout.fragmentsStack.isEmpty()) {
                        for (int a3 = 0; a3 < this.layersActionBarLayout.fragmentsStack.size() - 1; a3 = (a3 - 1) + 1) {
                            ActionBarLayout actionBarLayout7 = this.layersActionBarLayout;
                            actionBarLayout7.removeFragmentFromStack(actionBarLayout7.fragmentsStack.get(0));
                        }
                        this.layersActionBarLayout.closeLastFragment(!forceWithoutAnimation);
                    }
                    return false;
                }
                if (!this.layersActionBarLayout.fragmentsStack.isEmpty()) {
                    for (int a4 = 0; a4 < this.layersActionBarLayout.fragmentsStack.size() - 1; a4 = (a4 - 1) + 1) {
                        ActionBarLayout actionBarLayout8 = this.layersActionBarLayout;
                        actionBarLayout8.removeFragmentFromStack(actionBarLayout8.fragmentsStack.get(0));
                    }
                    this.layersActionBarLayout.closeLastFragment(!forceWithoutAnimation);
                }
                ActionBarLayout actionBarLayout9 = this.actionBarLayout;
                actionBarLayout9.presentFragment(fragment, actionBarLayout9.fragmentsStack.size() > 1, forceWithoutAnimation, false, false);
                return false;
            }
            ActionBarLayout actionBarLayout10 = this.layersActionBarLayout;
            if (layout == actionBarLayout10) {
                return true;
            }
            actionBarLayout10.setVisibility(0);
            this.drawerLayoutContainer.setAllowOpenDrawer(false, true);
            if (fragment instanceof LoginContronllerActivity) {
                this.backgroundTablet.setVisibility(0);
                this.shadowTabletSide.setVisibility(8);
                this.shadowTablet.setBackgroundColor(0);
            } else {
                this.shadowTablet.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
            }
            this.layersActionBarLayout.presentFragment(fragment, removeLast, forceWithoutAnimation, false, false);
            return false;
        }
        if (fragment instanceof LoginContronllerActivity) {
            if (mainFragmentsStack.size() == 0) {
            }
        } else if ((fragment instanceof CountrySelectActivity) && mainFragmentsStack.size() == 1) {
        }
        this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.ActionBarLayoutDelegate
    public boolean needAddFragmentToStack(BaseFragment fragment, ActionBarLayout layout) {
        ActionBarLayout actionBarLayout;
        ActionBarLayout actionBarLayout2;
        if (AndroidUtilities.isTablet()) {
            this.drawerLayoutContainer.setAllowOpenDrawer(false, true);
            if (fragment instanceof IndexActivity) {
                ActionBarLayout actionBarLayout3 = this.actionBarLayout;
                if (layout != actionBarLayout3) {
                    actionBarLayout3.removeAllFragments();
                    this.actionBarLayout.addFragmentToStack(fragment);
                    this.layersActionBarLayout.removeAllFragments();
                    this.layersActionBarLayout.setVisibility(8);
                    this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
                    if (!this.tabletFullSize) {
                        this.shadowTabletSide.setVisibility(0);
                        if (this.rightActionBarLayout.fragmentsStack.isEmpty()) {
                            this.backgroundTablet.setVisibility(0);
                        }
                    }
                    return false;
                }
            } else if ((fragment instanceof ChatActivity) && !((ChatActivity) fragment).isInScheduleMode()) {
                if (!this.tabletFullSize && layout != (actionBarLayout2 = this.rightActionBarLayout)) {
                    actionBarLayout2.setVisibility(0);
                    this.backgroundTablet.setVisibility(8);
                    this.rightActionBarLayout.removeAllFragments();
                    this.rightActionBarLayout.addFragmentToStack(fragment);
                    if (!this.layersActionBarLayout.fragmentsStack.isEmpty()) {
                        for (int a = 0; a < this.layersActionBarLayout.fragmentsStack.size() - 1; a = (a - 1) + 1) {
                            ActionBarLayout actionBarLayout4 = this.layersActionBarLayout;
                            actionBarLayout4.removeFragmentFromStack(actionBarLayout4.fragmentsStack.get(0));
                        }
                        this.layersActionBarLayout.closeLastFragment(true);
                    }
                    return false;
                }
                if (this.tabletFullSize && layout != (actionBarLayout = this.actionBarLayout)) {
                    actionBarLayout.addFragmentToStack(fragment);
                    if (!this.layersActionBarLayout.fragmentsStack.isEmpty()) {
                        for (int a2 = 0; a2 < this.layersActionBarLayout.fragmentsStack.size() - 1; a2 = (a2 - 1) + 1) {
                            ActionBarLayout actionBarLayout5 = this.layersActionBarLayout;
                            actionBarLayout5.removeFragmentFromStack(actionBarLayout5.fragmentsStack.get(0));
                        }
                        this.layersActionBarLayout.closeLastFragment(true);
                    }
                    return false;
                }
            } else {
                ActionBarLayout actionBarLayout6 = this.layersActionBarLayout;
                if (layout != actionBarLayout6) {
                    actionBarLayout6.setVisibility(0);
                    this.drawerLayoutContainer.setAllowOpenDrawer(false, true);
                    if (fragment instanceof LoginContronllerActivity) {
                        this.backgroundTablet.setVisibility(0);
                        this.shadowTabletSide.setVisibility(8);
                        this.shadowTablet.setBackgroundColor(0);
                    } else {
                        this.shadowTablet.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
                    }
                    this.layersActionBarLayout.addFragmentToStack(fragment);
                    return false;
                }
            }
            return true;
        }
        if (fragment instanceof LoginContronllerActivity) {
            if (mainFragmentsStack.size() == 0) {
            }
        } else if ((fragment instanceof CountrySelectActivity) && mainFragmentsStack.size() == 1) {
        }
        this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.ActionBarLayoutDelegate
    public boolean needCloseLastFragment(ActionBarLayout layout) {
        if (AndroidUtilities.isTablet()) {
            if (layout == this.actionBarLayout && layout.fragmentsStack.size() <= 1) {
                onFinish();
                finish();
                return false;
            }
            if (layout == this.rightActionBarLayout) {
                if (!this.tabletFullSize) {
                    this.backgroundTablet.setVisibility(0);
                }
            } else if (layout == this.layersActionBarLayout && this.actionBarLayout.fragmentsStack.isEmpty() && this.layersActionBarLayout.fragmentsStack.size() == 1) {
                onFinish();
                finish();
                return false;
            }
        } else {
            if (layout.fragmentsStack.size() <= 1) {
                onFinish();
                finish();
                return false;
            }
            if (layout.fragmentsStack.size() >= 2 && !(layout.fragmentsStack.get(0) instanceof LoginContronllerActivity)) {
                this.drawerLayoutContainer.setAllowOpenDrawer(false, false);
            }
        }
        return true;
    }

    public void rebuildAllFragments(boolean last) {
        ActionBarLayout actionBarLayout = this.layersActionBarLayout;
        if (actionBarLayout != null) {
            actionBarLayout.rebuildAllFragmentViews(last, last);
        } else {
            this.actionBarLayout.rebuildAllFragmentViews(last, last);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarLayout.ActionBarLayoutDelegate
    public void onRebuildAllFragments(ActionBarLayout layout, boolean last) {
        if (AndroidUtilities.isTablet() && layout == this.layersActionBarLayout) {
            this.rightActionBarLayout.rebuildAllFragmentViews(last, last);
            this.actionBarLayout.rebuildAllFragmentViews(last, last);
        }
        this.drawerLayoutAdapter.notifyDataSetChanged();
    }

    private void createGamePlayingFloatingView() {
        if (this.drawerLayoutContainer == null) {
            return;
        }
        DiscoveryJumpPausedFloatingView.getInstance().setContext(this).setRootViewContainer(this.drawerLayoutContainer).setActionBarLayout(this.actionBarLayout).show(true);
    }
}
