package im.uwrkaxlmjj.ui.fragments;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.RespFcUserStatisticsBean;
import com.blankj.utilcode.util.AppUtils;
import com.blankj.utilcode.util.ScreenUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.network.OSSChat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCFriendsHub;
import im.uwrkaxlmjj.ui.CacheControlActivity;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.McShareDialog;
import im.uwrkaxlmjj.ui.hcells.IndexTextCell2;
import im.uwrkaxlmjj.ui.hui.cdnvip.CdnVipCenterActivity;
import im.uwrkaxlmjj.ui.hui.mine.AboutAppActivity;
import im.uwrkaxlmjj.ui.hui.mine.MryLanguageSelectActivity;
import im.uwrkaxlmjj.ui.hui.mine.MryThemeActivity;
import im.uwrkaxlmjj.ui.hui.mine.NewUserInfoActivity;
import im.uwrkaxlmjj.ui.hui.mine.PrivacyAndSafeActivity;
import im.uwrkaxlmjj.ui.hui.mine.QrCodeActivity;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.sliding.SlidingLayout;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import im.uwrkaxlmjj.ui.settings.NoticeAndSoundSettingActivity;
import im.uwrkaxlmjj.ui.wallet.WalletActivity;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParserException;

/* JADX INFO: loaded from: classes5.dex */
public class MeFragmentV2 extends BaseFmts implements NotificationCenter.NotificationCenterDelegate {
    private BackupImageView avatarImage;
    private RespFcUserStatisticsBean fcActionCountBean;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private int pressCount;
    private int rowCount;
    private TLRPC.UserFull userFull;
    private int avatarRow = -1;
    private int avatarEmptyRow = -1;
    private int pcLoginRow = -1;
    private int digitalcurrency = -1;
    private int liveIncomeRow = -1;
    private int digitalcurrencyEmptyRow = -1;
    private int cdnVipRow = -1;
    private int cdnVipEmptyRow = -1;
    private int newWalletRow = -1;
    private int newWalletEmptyRow = -1;
    private int gamesCenterEmptyRow = -1;
    private int notifyRow = -1;
    private int privacyRow = -1;
    private int dataRow = -1;
    private int uploadLog = -1;
    private int appearanceRow = -1;
    private int langRow = -1;
    private int dataEmptyRow = -1;
    private int faqRow = -1;
    private int aboutRow = -1;
    private int inviteFriends = -1;
    private int serviceRow = -1;
    private int serviceEmptyRow = -1;
    private String TAG = MeFragmentV2.class.getSimpleName();
    private boolean isRequestActionCount = false;
    private PhotoViewer.PhotoViewerProvider provider = new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.fragments.MeFragmentV2.2
        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public PhotoViewer.PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
            TLRPC.User user;
            if (fileLocation != null && (user = MessagesController.getInstance(MeFragmentV2.this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(MeFragmentV2.this.currentAccount).getClientUserId()))) != null && user.photo != null && user.photo.photo_big != null) {
                TLRPC.FileLocation photoBig = user.photo.photo_big;
                if (photoBig.local_id == fileLocation.local_id && photoBig.volume_id == fileLocation.volume_id && photoBig.dc_id == fileLocation.dc_id) {
                    int[] coords = new int[2];
                    MeFragmentV2.this.avatarImage.getLocationInWindow(coords);
                    PhotoViewer.PlaceProviderObject object = new PhotoViewer.PlaceProviderObject();
                    object.viewX = coords[0];
                    object.viewY = coords[1] - (Build.VERSION.SDK_INT < 21 ? AndroidUtilities.statusBarHeight : 0);
                    object.parentView = MeFragmentV2.this.avatarImage;
                    object.imageReceiver = MeFragmentV2.this.avatarImage.getImageReceiver();
                    object.dialogId = UserConfig.getInstance(MeFragmentV2.this.currentAccount).getClientUserId();
                    object.thumb = object.imageReceiver.getBitmapSafe();
                    object.size = -1;
                    object.radius = MeFragmentV2.this.avatarImage.getImageReceiver().getRoundRadius();
                    object.scale = MeFragmentV2.this.avatarImage.getScaleX();
                    return object;
                }
            }
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void willHidePhotoViewer() {
            MeFragmentV2.this.avatarImage.getImageReceiver().setVisible(true, true);
        }
    };

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        updateRows();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.cdnVipBuySuccess);
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        final Context context = getContext();
        SlidingLayout root = new SlidingLayout(context);
        this.fragmentView = root;
        root.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setHasFixedSize(true);
        this.listView.setNestedScrollingEnabled(false);
        this.listView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.listView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        root.addView(this.listView, LayoutHelper.createFrame(-1, -1, 51));
        MryTextView tvVersion = new MryTextView(context);
        tvVersion.setTextSize(12.0f);
        tvVersion.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        tvVersion.setText(LocaleController.getString(R.string.AppName) + "Android Client v" + AppUtils.getAppVersionName());
        root.addView(tvVersion, LayoutHelper.createFrame(-2.0f, -2.0f, 81, 0.0f, 0.0f, 0.0f, (float) AndroidUtilities.dp(10.0f)));
        tvVersion.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$lErsJ_BelDbt4x3xlIbbE9y4LlY
            @Override // android.view.View.OnLongClickListener
            public final boolean onLongClick(View view) {
                return this.f$0.lambda$onCreateView$0$MeFragmentV2(view);
            }
        });
        ListAdapter listAdapter = new ListAdapter(context);
        this.listAdapter = listAdapter;
        this.listView.setAdapter(listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$5uRulBkgYwMixrlr_p3xolp91Dk
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$onCreateView$1$MeFragmentV2(context, view, i);
            }
        });
        return root;
    }

    public /* synthetic */ boolean lambda$onCreateView$0$MeFragmentV2(View v) {
        LogUpLoad.uploadLogFile(getUserConfig().clientUserId);
        return true;
    }

    public /* synthetic */ void lambda$onCreateView$1$MeFragmentV2(Context context, View view, int position) {
        if (position != this.avatarRow) {
            if (position == this.newWalletRow) {
                presentFragment(new WalletActivity());
                return;
            }
            if (position == this.notifyRow) {
                presentFragment(new NoticeAndSoundSettingActivity());
                return;
            }
            if (position == this.privacyRow) {
                presentFragment(new PrivacyAndSafeActivity());
                return;
            }
            if (position == this.dataRow) {
                presentFragment(new CacheControlActivity());
                return;
            }
            if (position == this.uploadLog) {
                LogUpLoad.uploadLogFile(getUserConfig().clientUserId);
                return;
            }
            if (position == this.appearanceRow) {
                presentFragment(new MryThemeActivity(0));
                return;
            }
            if (position == this.langRow) {
                presentFragment(new MryLanguageSelectActivity());
                return;
            }
            if (position == this.aboutRow) {
                presentFragment(new AboutAppActivity());
                return;
            }
            if (position == this.inviteFriends) {
                McShareDialog mcShareDialog = new McShareDialog(context, this);
                mcShareDialog.setUser(getUserConfig().getCurrentUser());
                mcShareDialog.initData();
                return;
            }
            if (position == this.serviceRow) {
                getServerUrl();
                return;
            }
            if (position != this.digitalcurrency && position != this.liveIncomeRow) {
                if (position == this.cdnVipRow) {
                    presentFragment(new CdnVipCenterActivity());
                    return;
                }
                if (position == this.pcLoginRow) {
                    ToastUtils.show((CharSequence) "Developing...");
                    return;
                }
                if (position == this.faqRow) {
                    ToastUtils.show((CharSequence) "Developing...");
                } else {
                    if (position != this.gamesCenterEmptyRow || position != this.dataEmptyRow || position != this.serviceEmptyRow) {
                        return;
                    }
                    ToastUtils.show(R.string.NotSupport);
                }
            }
        }
    }

    private void getServerUrl() {
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        showDialog(progressDialog);
        OSSChat.getInstance().sendOSSRequest(new OSSChat.OSSChatCallback() { // from class: im.uwrkaxlmjj.ui.fragments.MeFragmentV2.1
            @Override // im.uwrkaxlmjj.network.OSSChat.OSSChatCallback
            public void onSuccess(String url) {
                progressDialog.dismiss();
                Log.d("bond", "客服链接 = " + url);
                Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(url));
                intent.putExtra("create_new_tab", true);
                intent.putExtra("com.android.browser.application_id", MeFragmentV2.this.getParentActivity().getPackageName());
                MeFragmentV2.this.getParentActivity().startActivity(intent);
            }

            @Override // im.uwrkaxlmjj.network.OSSChat.OSSChatCallback
            public void onFail() {
                progressDialog.dismiss();
                ToastUtils.show((CharSequence) "获取客服链接失败");
            }
        });
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        MessagesController.getInstance(this.currentAccount).loadUserInfo(UserConfig.getInstance(this.currentAccount).getCurrentUser(), true, this.classGuid);
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void lazyLoadData() {
        super.lazyLoadData();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    public void onResumeForBaseFragment() {
        super.onResumeForBaseFragment();
        if (!BuildVars.DEBUG_VERSION) {
            getFcLocation();
        }
        getActionCount();
        if (this.listAdapter != null && !isFirstTimeInThisPage()) {
            this.listAdapter.notifyDataSetChanged();
        }
    }

    private void getActionCount() {
    }

    private void updateRows() {
        this.avatarRow = -1;
        this.avatarEmptyRow = -1;
        this.newWalletRow = -1;
        this.gamesCenterEmptyRow = -1;
        this.digitalcurrency = -1;
        this.digitalcurrencyEmptyRow = -1;
        this.liveIncomeRow = -1;
        this.notifyRow = -1;
        this.privacyRow = -1;
        this.dataRow = -1;
        this.uploadLog = -1;
        this.appearanceRow = -1;
        this.langRow = -1;
        this.dataEmptyRow = -1;
        this.aboutRow = -1;
        this.serviceRow = -1;
        this.serviceEmptyRow = -1;
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.avatarRow = 0;
        this.rowCount = i + 1;
        this.avatarEmptyRow = i;
        if (BuildVars.WALLET_ENABLE) {
            int i2 = this.rowCount;
            int i3 = i2 + 1;
            this.rowCount = i3;
            this.newWalletRow = i2;
            this.rowCount = i3 + 1;
            this.newWalletEmptyRow = i3;
        }
        int i4 = this.rowCount;
        int i5 = i4 + 1;
        this.rowCount = i5;
        this.privacyRow = i4;
        int i6 = i5 + 1;
        this.rowCount = i6;
        this.notifyRow = i5;
        int i7 = i6 + 1;
        this.rowCount = i7;
        this.langRow = i6;
        int i8 = i7 + 1;
        this.rowCount = i8;
        this.dataEmptyRow = i7;
        int i9 = i8 + 1;
        this.rowCount = i9;
        this.dataRow = i8;
        this.rowCount = i9 + 1;
        this.uploadLog = i9;
        boolean z = BuildVars.ENABLE_ME_ONLINE_SERVICE;
        if (BuildVars.ENABLE_ME_ABOUT_APP) {
            int i10 = this.rowCount;
            this.rowCount = i10 + 1;
            this.aboutRow = i10;
        }
        boolean z2 = BuildVars.ENABLE_ME_ONLINE_SERVICE;
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        BackupImageView backupImageView = this.avatarImage;
        if (backupImageView != null) {
            backupImageView.setImageDrawable(null);
        }
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.cdnVipBuySuccess);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        ListAdapter listAdapter;
        if (id == NotificationCenter.updateInterfaces) {
            int mask = ((Integer) args[0]).intValue();
            if (((mask & 2) != 0 || (mask & 1) != 0) && (listAdapter = this.listAdapter) != null) {
                listAdapter.notifyItemChanged(this.avatarRow);
                return;
            }
            return;
        }
        if (id == NotificationCenter.userFullInfoDidLoad) {
            int userId = ((Integer) args[0]).intValue();
            if (userId == UserConfig.getInstance(this.currentAccount).getClientUserId()) {
                this.userFull = (TLRPC.UserFull) args[1];
                NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFullInfoDidLoad);
                ListAdapter listAdapter2 = this.listAdapter;
                if (listAdapter2 != null) {
                    listAdapter2.notifyItemChanged(this.avatarRow);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.cdnVipBuySuccess) {
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFullInfoDidLoad);
            MessagesController.getInstance(this.currentAccount).loadFullUser(UserConfig.getInstance(this.currentAccount).getCurrentUser(), this.classGuid, true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void saveImage(final File file) {
        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$p3LvuS9Ik0HJcchVDlse3u5X-lo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveImage$2$MeFragmentV2(file);
            }
        }).start();
    }

    public /* synthetic */ void lambda$saveImage$2$MeFragmentV2(File file) {
        try {
            if (file.exists()) {
                file.delete();
            }
            while (this.avatarImage.getImageReceiver().getBitmap() == null) {
                Thread.sleep(10L);
            }
            Bitmap bitmap = this.avatarImage.getImageReceiver().getBitmap();
            FileOutputStream out = new FileOutputStream(file);
            bitmap.compress(Bitmap.CompressFormat.JPEG, 100, out);
            out.flush();
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* JADX INFO: renamed from: notifyUpdateWalletRow, reason: merged with bridge method [inline-methods] */
    public void lambda$null$3$MeFragmentV2() {
        if (this.listAdapter != null) {
            updateRows();
            this.listAdapter.notifyDataSetChanged();
        }
    }

    private void getFcLocation() {
        TLRPCFriendsHub.TL_GetOtherConfig req = new TLRPCFriendsHub.TL_GetOtherConfig();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$1uPQTopnwT-aTZF8CpyrJfGklyg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getFcLocation$4$MeFragmentV2(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$getFcLocation$4$MeFragmentV2(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            FileLog.e("get friend hub base url failed" + error.text);
            return;
        }
        TLRPCFriendsHub.TL_OtherConfig result = (TLRPCFriendsHub.TL_OtherConfig) response;
        try {
            if (result.data != null && !TextUtils.isEmpty(result.data.data)) {
                JSONObject jsonObject = new JSONObject(result.data.data);
                int payTurn = jsonObject.getInt("PayTurn");
                boolean z = true;
                if (payTurn != 1) {
                    z = false;
                }
                if (z != BuildVars.WALLET_ENABLE) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$px_DOGtZql_Tp5NBmz2gTahzhY4
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$3$MeFragmentV2();
                        }
                    });
                }
            }
        } catch (Exception e) {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return MeFragmentV2.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            Drawable drawable;
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                IndexTextCell2 cell = (IndexTextCell2) holder.itemView;
                if (position != MeFragmentV2.this.pcLoginRow) {
                    if (position != MeFragmentV2.this.digitalcurrency) {
                        if (position != MeFragmentV2.this.liveIncomeRow) {
                            if (position != MeFragmentV2.this.cdnVipRow) {
                                if (position != MeFragmentV2.this.notifyRow) {
                                    if (position != MeFragmentV2.this.privacyRow) {
                                        if (position != MeFragmentV2.this.appearanceRow) {
                                            if (position != MeFragmentV2.this.dataRow) {
                                                if (position != MeFragmentV2.this.uploadLog) {
                                                    if (position != MeFragmentV2.this.langRow) {
                                                        if (position != MeFragmentV2.this.faqRow) {
                                                            if (position != MeFragmentV2.this.aboutRow) {
                                                                if (position != MeFragmentV2.this.serviceRow) {
                                                                    if (position == MeFragmentV2.this.inviteFriends) {
                                                                        cell.setTextAndIcon(LocaleController.getString("MeInviteFriends", R.string.MeInviteFriends), R.drawable.fmt_mev2_friends, R.id.icon_arrow_right, true);
                                                                        return;
                                                                    }
                                                                    return;
                                                                }
                                                                cell.setTextAndIcon(LocaleController.getString("OnlineService", R.string.OnlineService), R.drawable.fmt_mev2_service, R.id.icon_arrow_right, true);
                                                                return;
                                                            }
                                                            cell.setTextAndIcon(LocaleController.getString("AboutApp", R.string.AboutApp), R.drawable.fmt_mev2_about, R.id.icon_arrow_right, false);
                                                            cell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                                                            return;
                                                        }
                                                        cell.setTextAndIcon(LocaleController.getString("faq", R.string.faq), R.drawable.fmt_mev2_faq, R.id.icon_arrow_right, true);
                                                        return;
                                                    }
                                                    cell.setTextAndIcon(LocaleController.getString("LanguageSetting", R.string.LanguageSetting), R.drawable.fmt_mev2_lang, R.id.icon_arrow_right, false);
                                                    cell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                                                    return;
                                                }
                                                cell.setTextAndIcon(LocaleController.getString("UpLoadLog", R.string.UpLoadLog), R.drawable.icon_upload_log, R.id.icon_arrow_right, false);
                                                return;
                                            }
                                            cell.setTextAndIcon(LocaleController.getString("ClearMediaCache", R.string.ClearMediaCache), R.drawable.icon_clearcache, R.id.icon_arrow_right, false);
                                            return;
                                        }
                                        cell.setTextAndIcon(LocaleController.getString("Appearance", R.string.Appearance), R.drawable.fmt_mev2_theme, R.id.icon_arrow_right, true);
                                        return;
                                    }
                                    cell.setTextAndIcon(LocaleController.getString("PrivacySettings", R.string.PrivacySettings), R.drawable.fmt_mev2_privacy, R.id.icon_arrow_right, true);
                                    cell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                                    return;
                                }
                                cell.setTextAndIcon(LocaleController.getString("NotificationsAndSounds", R.string.NotificationsAndSounds), R.drawable.fmt_mev2_notify, R.id.icon_arrow_right, true);
                                return;
                            }
                            cell.setTextAndIcon(LocaleController.getString("OpenCdnVip", R.string.OpenCdnVip), R.drawable.fmt_live_income, R.id.icon_arrow_right, false);
                            cell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                            return;
                        }
                        cell.setTextAndIcon(LocaleController.getString("LiveIncome", R.string.LiveIncome), R.drawable.fmt_live_income, R.id.icon_arrow_right, false);
                        cell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                        return;
                    }
                    cell.setTextAndIcon(LocaleController.getString("digitalcurrency", R.string.digitalcurrency), R.drawable.fmt_mev2_digitalcurrency, R.id.icon_arrow_right, true);
                    cell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                cell.setTextAndIcon("PC版登录", R.id.fmt_me_pc, R.id.icon_arrow_right, true);
                cell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                return;
            }
            if (itemViewType != 1) {
                if (itemViewType == 2) {
                    IndexTextCell2 cell2 = (IndexTextCell2) holder.itemView;
                    if (MeFragmentV2.this.newWalletRow == holder.getAdapterPosition()) {
                        cell2.setTextAndIcon(LocaleController.getString("WalletCenter", R.string.WalletCenter), R.id.fmt_me_wallet, R.id.icon_arrow_right, false);
                        cell2.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                        return;
                    } else {
                        ((IndexTextCell2) holder.itemView).setTextAndIcon(LocaleController.getString("WalletCenter", R.string.WalletCenter), R.id.fmt_me_wallet, R.id.icon_arrow_right, false);
                        return;
                    }
                }
                if (itemViewType == 3) {
                    View sectionCell = holder.itemView;
                    ((IndexTextCell2) sectionCell).setTextAndIcon(LocaleController.getString("GameCenter", R.string.GameCenter), R.id.fmt_me_games, R.id.icon_arrow_right, false);
                    return;
                } else {
                    if (itemViewType == 4) {
                        View sectionCell2 = holder.itemView;
                        sectionCell2.setTag(Integer.valueOf(position));
                        if (position == MeFragmentV2.this.serviceEmptyRow) {
                            drawable = Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow);
                        } else {
                            drawable = Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow);
                        }
                        CombinedDrawable combinedDrawable = new CombinedDrawable(new ColorDrawable(Theme.getColor(Theme.key_windowBackgroundGray)), drawable);
                        combinedDrawable.setFullsize(true);
                        return;
                    }
                    return;
                }
            }
            FrameLayout frameLayout = (FrameLayout) holder.itemView.findViewById(R.attr.containerLayout);
            frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            ImageView ivHeaderQRCode = (ImageView) holder.itemView.findViewById(R.attr.ivHeaderQRCode);
            MeFragmentV2.this.avatarImage = (BackupImageView) holder.itemView.findViewById(R.attr.bivHeaderAvatar);
            TextView tvUsername = (TextView) holder.itemView.findViewById(R.attr.tvUsername);
            TextView tvuernum = (TextView) holder.itemView.findViewById(R.attr.tvuernum);
            View parentUserName = holder.itemView.findViewById(R.attr.parentUserName);
            parentUserName.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$ListAdapter$kFjkwDmye5egl3bG-sfrwHWjFGw
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onBindViewHolder$0$MeFragmentV2$ListAdapter(view);
                }
            });
            TLRPC.User user = UserConfig.getInstance(UserConfig.selectedAccount).getCurrentUser();
            if (user == null) {
                return;
            }
            Drawable drawable2 = MeFragmentV2.this.getResources().getDrawable(R.drawable.ic_head_def);
            tvUsername.setText(UserObject.getName(user));
            int unMaxWidth = ScreenUtils.getScreenWidth() - AndroidUtilities.dp(197.0f);
            if (unMaxWidth > 0) {
                tvUsername.setMaxWidth(unMaxWidth);
            }
            MeFragmentV2.this.avatarImage.setRoundRadius(AndroidUtilities.dp(7.5f));
            MeFragmentV2.this.avatarImage.getImageReceiver().setCurrentAccount(MeFragmentV2.this.currentAccount);
            MeFragmentV2.this.avatarImage.setImage(ImageLocation.getForUser(user, false), "50_50", drawable2, user);
            holder.itemView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$ListAdapter$VJ_JwU6YZGASprAkCTfEm7T4nE8
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onBindViewHolder$1$MeFragmentV2$ListAdapter(view);
                }
            });
            tvuernum.setText(LocaleController.getString("AppNameCode", R.string.AppNameCode) + " : " + user.username);
            MeFragmentV2.this.avatarImage.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$ListAdapter$ww_em0zJuD8335c_o8OM21_t8DY
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onBindViewHolder$2$MeFragmentV2$ListAdapter(view);
                }
            });
            File file = new File(AndroidUtilities.getCacheDir().getPath() + File.separator + "user_avatar.jpg");
            if (user.photo instanceof TLRPC.TL_userProfilePhoto) {
                MeFragmentV2.this.saveImage(file);
            } else if (file.exists()) {
                file.delete();
            }
            ivHeaderQRCode.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$ListAdapter$cPURSYW-3pZnMQxW0FpN3omXsiE
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onBindViewHolder$3$MeFragmentV2$ListAdapter(view);
                }
            });
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$MeFragmentV2$ListAdapter(View v) {
            MeFragmentV2.this.presentFragment(new NewUserInfoActivity());
        }

        public /* synthetic */ void lambda$onBindViewHolder$1$MeFragmentV2$ListAdapter(View v) {
            MeFragmentV2.this.presentFragment(new NewUserInfoActivity());
        }

        public /* synthetic */ void lambda$onBindViewHolder$2$MeFragmentV2$ListAdapter(View v) {
            TLRPC.User user1 = MessagesController.getInstance(MeFragmentV2.this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(MeFragmentV2.this.currentAccount).getClientUserId()));
            if (user1 != null && user1.photo != null && user1.photo.photo_big != null) {
                PhotoViewer.getInstance().setParentActivity(MeFragmentV2.this.getParentActivity());
                if (user1.photo.dc_id != 0) {
                    user1.photo.photo_big.dc_id = user1.photo.dc_id;
                }
                PhotoViewer.getInstance().openPhoto(user1.photo.photo_big, MeFragmentV2.this.provider);
            }
        }

        public /* synthetic */ void lambda$onBindViewHolder$3$MeFragmentV2$ListAdapter(View v) {
            QrCodeActivity qrCodeActivity = new QrCodeActivity(MeFragmentV2.this.getUserConfig().getClientUserId());
            MeFragmentV2.this.presentFragment(qrCodeActivity);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == MeFragmentV2.this.avatarRow || position == MeFragmentV2.this.pcLoginRow || position == MeFragmentV2.this.aboutRow || position == MeFragmentV2.this.notifyRow || position == MeFragmentV2.this.privacyRow || position == MeFragmentV2.this.dataRow || position == MeFragmentV2.this.digitalcurrency || position == MeFragmentV2.this.cdnVipRow || position == MeFragmentV2.this.faqRow || position == MeFragmentV2.this.appearanceRow || position == MeFragmentV2.this.langRow || position == MeFragmentV2.this.serviceRow || position == MeFragmentV2.this.newWalletRow || position == MeFragmentV2.this.uploadLog;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new IndexTextCell2(this.mContext, AndroidUtilities.dp(1.0f));
                RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(-1, -2);
                layoutParams.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 1) {
                view = LayoutInflater.from(this.mContext).inflate(R.layout.fmt_header_layout, (ViewGroup) null, false);
                view.findViewById(R.attr.ivHeaderQRCode);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(200.0f)));
            } else if (viewType == 2) {
                view = new IndexTextCell2(this.mContext);
                RecyclerView.LayoutParams layoutParams2 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams2.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams2.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams2);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 3) {
                view = new IndexTextCell2(this.mContext);
                RecyclerView.LayoutParams layoutParams3 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams3.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams3.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams3);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 4) {
                view = new View(this.mContext);
                RecyclerView.LayoutParams layoutParams4 = new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(10.0f));
                layoutParams4.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams4.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams4);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != MeFragmentV2.this.avatarRow) {
                if (position != MeFragmentV2.this.newWalletRow) {
                    if (position == MeFragmentV2.this.gamesCenterEmptyRow || position == MeFragmentV2.this.dataEmptyRow || position == MeFragmentV2.this.serviceEmptyRow || position == MeFragmentV2.this.newWalletEmptyRow || position == MeFragmentV2.this.digitalcurrencyEmptyRow || position == MeFragmentV2.this.avatarEmptyRow || position == MeFragmentV2.this.cdnVipEmptyRow) {
                        return 4;
                    }
                    return 0;
                }
                return 2;
            }
            return 1;
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void onDialogDismiss(Dialog dialog) {
        super.onDialogDismiss(dialog);
        this.pressCount = 0;
    }

    private void sendLogs() {
        if (getParentActivity() == null) {
            return;
        }
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setCanCancel(false);
        progressDialog.show();
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$GNj4OFvQrgLBMOJyG_ZIjGtVK1g
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$sendLogs$6$MeFragmentV2(progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$sendLogs$6$MeFragmentV2(final AlertDialog progressDialog) {
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
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$fLDqO9MjBSqbE8q1TzfKAraBA8E
                            @Override // java.lang.Runnable
                            public final void run() throws XmlPullParserException, IOException {
                                this.f$0.lambda$null$5$MeFragmentV2(progressDialog, finished, zipFile);
                            }
                        });
                    }
                    out.close();
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$fLDqO9MjBSqbE8q1TzfKAraBA8E
                        @Override // java.lang.Runnable
                        public final void run() throws XmlPullParserException, IOException {
                            this.f$0.lambda$null$5$MeFragmentV2(progressDialog, finished, zipFile);
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

    public /* synthetic */ void lambda$null$5$MeFragmentV2(AlertDialog progressDialog, boolean[] finished, File zipFile) throws XmlPullParserException, IOException {
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

    public static void performService(final BaseFragment fragment) {
        String userString;
        if (fragment == null || fragment.getParentActivity() == null) {
            return;
        }
        final int currentAccount = fragment.getCurrentAccount();
        final SharedPreferences preferences = MessagesController.getMainSettings(currentAccount);
        int uid = preferences.getInt("support_id", 0);
        TLRPC.User supportUser = null;
        if (uid != 0 && (supportUser = MessagesController.getInstance(currentAccount).getUser(Integer.valueOf(uid))) == null && (userString = preferences.getString("support_user", null)) != null) {
            try {
                byte[] datacentersBytes = Base64.decode(userString, 0);
                if (datacentersBytes != null) {
                    SerializedData data = new SerializedData(datacentersBytes);
                    supportUser = TLRPC.User.TLdeserialize(data, data.readInt32(false), false);
                    if (supportUser != null && supportUser.id == 333000) {
                        supportUser = null;
                    }
                    data.cleanup();
                }
            } catch (Exception e) {
                FileLog.e(e);
                supportUser = null;
            }
        }
        if (supportUser != null) {
            MessagesController.getInstance(currentAccount).putUser(supportUser, true);
            Bundle args = new Bundle();
            args.putInt("user_id", supportUser.id);
            fragment.presentFragment(new ChatActivity(args));
            return;
        }
        final AlertDialog progressDialog = new AlertDialog(fragment.getParentActivity(), 3);
        progressDialog.setCanCancel(true);
        progressDialog.show();
        TLRPC.TL_help_getSupport req = new TLRPC.TL_help_getSupport();
        final int requestToken = ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$I1y9W-Gzvp0Ma6-pV9ajT2tOOko
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                MeFragmentV2.lambda$performService$9(preferences, progressDialog, currentAccount, fragment, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$rQ44EjH8n8IyzXBBLk3RQaL6lW8
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                ConnectionsManager.getInstance(UserConfig.selectedAccount).cancelRequest(requestToken, true);
            }
        });
    }

    static /* synthetic */ void lambda$performService$9(final SharedPreferences preferences, final AlertDialog progressDialog, final int currentAccount, final BaseFragment fragment, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.TL_help_support res = (TLRPC.TL_help_support) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$5-ka3lU8cIsvHt-5bRM7Dgz-xIw
                @Override // java.lang.Runnable
                public final void run() {
                    MeFragmentV2.lambda$null$7(preferences, res, progressDialog, currentAccount, fragment);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$MeFragmentV2$Ns6rM_P9jeqjWd2tzep4g_1_xOI
                @Override // java.lang.Runnable
                public final void run() {
                    MeFragmentV2.lambda$null$8(progressDialog);
                }
            });
        }
    }

    static /* synthetic */ void lambda$null$7(SharedPreferences preferences, TLRPC.TL_help_support res, AlertDialog progressDialog, int currentAccount, BaseFragment fragment) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putInt("support_id", res.user.id);
        SerializedData data = new SerializedData();
        res.user.serializeToStream(data);
        editor.putString("support_user", Base64.encodeToString(data.toByteArray(), 0));
        editor.apply();
        data.cleanup();
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        ArrayList<TLRPC.User> users = new ArrayList<>();
        users.add(res.user);
        MessagesStorage.getInstance(currentAccount).putUsersAndChats(users, null, true, true);
        MessagesController.getInstance(currentAccount).putUser(res.user, false);
        Bundle args = new Bundle();
        args.putInt("user_id", res.user.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$null$8(AlertDialog progressDialog) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }
}
