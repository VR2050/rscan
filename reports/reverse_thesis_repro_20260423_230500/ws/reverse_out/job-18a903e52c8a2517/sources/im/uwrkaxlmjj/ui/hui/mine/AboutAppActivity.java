package im.uwrkaxlmjj.ui.hui.mine;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import androidx.core.widget.NestedScrollView;
import androidx.recyclerview.widget.LinearLayoutManager;
import com.bjz.comm.net.SPConstant;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.IpChangeActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.WebviewActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;
import im.uwrkaxlmjj.ui.constants.Constants;
import im.uwrkaxlmjj.ui.hcells.IndexTextCell;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import mpEIGo.juqQQs.esbSDO.R;
import org.xmlpull.v1.XmlPullParserException;

/* JADX INFO: loaded from: classes5.dex */
public class AboutAppActivity extends BaseFragment {
    private PageSelectionAdapter<Integer, PageHolder> adapter;
    private int pressCount;
    private RecyclerListView rv;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        initActionBar(context);
        this.fragmentView = initContentView(context);
        return this.fragmentView;
    }

    private void initActionBar(Context context) {
        this.actionBar = createActionBar(context);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.mine.AboutAppActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                super.onItemClick(id);
                if (id == -1) {
                    AboutAppActivity.this.finishFragment();
                }
            }
        });
        this.actionBar.setTitle(LocaleController.getString("AboutApp", R.string.AboutApp));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        getParentActivity().setRequestedOrientation(1);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        getParentActivity().setRequestedOrientation(2);
        super.onFragmentDestroy();
    }

    private View initContentView(Context context) {
        NestedScrollView nestedScrollView = new NestedScrollView(context);
        nestedScrollView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        nestedScrollView.setFillViewport(true);
        LinearLayout par = new LinearLayout(context);
        par.setOrientation(1);
        par.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        ImageView ivLogo = new ImageView(context);
        ivLogo.setImageResource(R.id.ic_logo);
        par.addView(ivLogo, LayoutHelper.createLinear(-2, -2, 1, 0, AndroidUtilities.dp(30.0f), 0, AndroidUtilities.dp(5.0f)));
        TextView tvAppName = new TextView(context);
        addTextView(par, tvAppName, 14, Theme.getColor(Theme.key_windowBackgroundWhiteBlackText), LocaleController.getString("AppName", R.string.AppName), LayoutHelper.createLinear(-2, -2, 1));
        TextView tvAppVersion = new TextView(context);
        addTextView(par, tvAppVersion, 13, Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2), LocaleController.getString("Version", R.string.Version) + " " + AndroidUtilities.getVersionName(context), LayoutHelper.createLinear(-2, -2, 1, 0, AndroidUtilities.dp(2.0f), 0, 0));
        tvAppVersion.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$AboutAppActivity$nPEl9lMgJszQZjYf1l9dE2ME35U
            @Override // android.view.View.OnLongClickListener
            public final boolean onLongClick(View view) {
                return this.f$0.lambda$initContentView$1$AboutAppActivity(view);
            }
        });
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.rv = recyclerListView;
        recyclerListView.setLayoutManager(new LinearLayoutManager(context));
        this.rv.setVerticalScrollBarEnabled(false);
        this.rv.setOverScrollMode(2);
        this.rv.setNestedScrollingEnabled(false);
        this.rv.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$AboutAppActivity$oV5R4wBq3AeY_bnMQJrLLHjil3U
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initContentView$2$AboutAppActivity(view, i);
            }
        });
        PageSelectionAdapter<Integer, PageHolder> pageSelectionAdapter = new PageSelectionAdapter<Integer, PageHolder>(getParentActivity()) { // from class: im.uwrkaxlmjj.ui.hui.mine.AboutAppActivity.2
            @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
            public PageHolder onCreateViewHolderForChild(ViewGroup parent, int viewType) {
                View view = new IndexTextCell(getContext());
                return new PageHolder(view);
            }

            @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
            public void onBindViewHolderForChild(PageHolder holder, int position, Integer item) {
                if (position == 0) {
                    ((IndexTextCell) holder.itemView).setTextAndIcon(LocaleController.getString("OnlineService", R.string.OnlineService), 0, R.id.icon_arrow_right, true);
                } else if (position == 1) {
                    ((IndexTextCell) holder.itemView).setTextAndIcon(LocaleController.getString("UserAgreementOnly", R.string.UserAgreementOnly), 0, R.id.icon_arrow_right, true);
                } else if (position == 2) {
                    ((IndexTextCell) holder.itemView).setTextAndIcon(LocaleController.getString("PrivacyPolicyWithoutBookTitleMark", R.string.PrivacyPolicyWithoutBookTitleMark), 0, R.id.icon_arrow_right, true);
                } else if (position == 3) {
                    ((IndexTextCell) holder.itemView).setTextAndIcon(LocaleController.getString("CheckForUpdates", R.string.CheckForUpdates), 0, R.id.icon_arrow_right, true);
                }
                holder.itemView.invalidate();
            }
        };
        this.adapter = pageSelectionAdapter;
        pageSelectionAdapter.setData(Arrays.asList(0, 1, 2, 3));
        this.adapter.setShowLoadMoreViewEnable(false);
        this.rv.setAdapter(this.adapter);
        LinearLayout.LayoutParams lp = LayoutHelper.createLinear(-1, 0, 1.0f);
        lp.topMargin = AndroidUtilities.dp(30.0f);
        par.addView(this.rv, lp);
        nestedScrollView.addView(par, LayoutHelper.createFrame(-1, -1.0f));
        return nestedScrollView;
    }

    public /* synthetic */ boolean lambda$initContentView$1$AboutAppActivity(View v) {
        int i;
        String str;
        int i2;
        String str2;
        boolean z = BuildVars.RELEASE_VERSION;
        int i3 = this.pressCount + 1;
        this.pressCount = i3;
        if (i3 >= 2) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("DebugMenu", R.string.DebugMenu));
            CharSequence[] items = new CharSequence[11];
            items[0] = LocaleController.getString("DebugSendLogs", R.string.DebugSendLogs);
            items[1] = LocaleController.getString("DebugClearLogs", R.string.DebugClearLogs);
            items[2] = LocaleController.getString("DebugMenuResetDialogs", R.string.DebugMenuResetDialogs);
            if (BuildVars.LOGS_ENABLED) {
                i = R.string.DebugMenuDisableLogs;
                str = "DebugMenuDisableLogs";
            } else {
                i = R.string.DebugMenuEnableLogs;
                str = "DebugMenuEnableLogs";
            }
            items[3] = LocaleController.getString(str, i);
            if (SharedConfig.inappCamera) {
                i2 = R.string.DebugMenuDisableCamera;
                str2 = "DebugMenuDisableCamera";
            } else {
                i2 = R.string.DebugMenuEnableCamera;
                str2 = "DebugMenuEnableCamera";
            }
            items[4] = LocaleController.getString(str2, i2);
            items[5] = LocaleController.getString("DebugMenuClearMediaCache", R.string.DebugMenuClearMediaCache);
            items[6] = LocaleController.getString("DebugMenuCallSettings", R.string.DebugMenuCallSettings);
            items[7] = null;
            items[8] = BuildVars.RELEASE_VERSION ? LocaleController.getString("CheckAppUpdates", R.string.CheckAppUpdates) : null;
            items[9] = LocaleController.getString("DebugMenuReadAllDialogs", R.string.DebugMenuReadAllDialogs);
            items[10] = BuildVars.RELEASE_VERSION ? null : "切换IP";
            builder.setItems(items, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$AboutAppActivity$t3Dub4c-cP1gn321ELF6dT27J9I
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i4) {
                    this.f$0.lambda$null$0$AboutAppActivity(dialogInterface, i4);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder.create());
        } else {
            try {
                ToastUtils.show((CharSequence) "¯\\_(ツ)_/¯");
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        return true;
    }

    public /* synthetic */ void lambda$null$0$AboutAppActivity(DialogInterface dialog, int which) {
        if (which == 0) {
            sendLogs();
            return;
        }
        if (which == 1) {
            FileLog.cleanupLogs();
            return;
        }
        if (which == 2) {
            MessagesController.getInstance(this.currentAccount).forceResetDialogs();
            return;
        }
        if (which == 3) {
            BuildVars.LOGS_ENABLED = true ^ BuildVars.LOGS_ENABLED;
            SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences(SPConstant.SP_SYSTEM_CONFIG, 0);
            sharedPreferences.edit().putBoolean("logsEnabled", BuildVars.LOGS_ENABLED).commit();
            return;
        }
        if (which == 4) {
            SharedConfig.toggleInappCamera();
            return;
        }
        if (which == 5) {
            MessagesStorage.getInstance(this.currentAccount).clearSentMedia();
            SharedConfig.setNoSoundHintShowed(false);
            SharedPreferences.Editor editor = MessagesController.getGlobalMainSettings().edit();
            editor.remove("archivehint").remove("archivehint_l").remove("gifhint").remove("soundHint").commit();
            return;
        }
        if (which == 6) {
            VoIPHelper.showCallDebugSettings(getParentActivity());
            return;
        }
        if (which == 7) {
            SharedConfig.toggleRoundCamera16to9();
            return;
        }
        if (which == 8) {
            ((LaunchActivity) getParentActivity()).checkAppUpdate(true);
        } else if (which == 9) {
            MessagesStorage.getInstance(this.currentAccount).readAllDialogs();
        } else if (which == 10) {
            presentFragment(new IpChangeActivity());
        }
    }

    public /* synthetic */ void lambda$initContentView$2$AboutAppActivity(View view, int position) {
        if (position == 0) {
            performService(this);
            return;
        }
        if (position == 1) {
            presentFragment(new WebviewActivity(Constants.URL_USER_AGREEMENT, (String) null));
        } else if (position == 2) {
            presentFragment(new WebviewActivity(Constants.URL_PRIVACY_POLICY, (String) null));
        } else if (position == 3) {
            ((LaunchActivity) getParentActivity()).checkAppUpdate(true);
        }
    }

    public void performService(final BaseFragment fragment) {
        String userString;
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
        if (supportUser == null) {
            final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
            progressDialog.show();
            TLRPC.TL_help_getSupport req = new TLRPC.TL_help_getSupport();
            ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$AboutAppActivity$HOZenaMZJbsGQbR-xqxOloHhtxc
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    AboutAppActivity.lambda$performService$5(preferences, progressDialog, currentAccount, fragment, tLObject, tL_error);
                }
            });
            return;
        }
        MessagesController.getInstance(currentAccount).putUser(supportUser, true);
        Bundle args = new Bundle();
        args.putInt("user_id", supportUser.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$performService$5(final SharedPreferences preferences, final XAlertDialog progressDialog, final int currentAccount, final BaseFragment fragment, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.TL_help_support res = (TLRPC.TL_help_support) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$AboutAppActivity$d1lepO4xEtkG_KYAFqS53vO4x7A
                @Override // java.lang.Runnable
                public final void run() {
                    AboutAppActivity.lambda$null$3(preferences, res, progressDialog, currentAccount, fragment);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$AboutAppActivity$2nq96dXvFf0wo3i4UlDUl6oq0BI
                @Override // java.lang.Runnable
                public final void run() {
                    AboutAppActivity.lambda$null$4(progressDialog);
                }
            });
        }
    }

    static /* synthetic */ void lambda$null$3(SharedPreferences preferences, TLRPC.TL_help_support res, XAlertDialog progressDialog, int currentAccount, BaseFragment fragment) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putInt("support_id", res.user.id);
        SerializedData data = new SerializedData();
        res.user.serializeToStream(data);
        editor.putString("support_user", Base64.encodeToString(data.toByteArray(), 0));
        editor.commit();
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

    static /* synthetic */ void lambda$null$4(XAlertDialog progressDialog) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void sendLogs() {
        if (getParentActivity() == null) {
            return;
        }
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setCanCancel(false);
        progressDialog.show();
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$AboutAppActivity$QueGvYA6JLE6AOd7tlhESQIMgQg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$sendLogs$7$AboutAppActivity(progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$sendLogs$7$AboutAppActivity(final AlertDialog progressDialog) {
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
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$AboutAppActivity$UUCzbI1m8fYU1BCbSPIWjH-U6lw
                            @Override // java.lang.Runnable
                            public final void run() throws XmlPullParserException, IOException {
                                this.f$0.lambda$null$6$AboutAppActivity(progressDialog, finished, zipFile);
                            }
                        });
                    }
                    out.close();
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$AboutAppActivity$UUCzbI1m8fYU1BCbSPIWjH-U6lw
                        @Override // java.lang.Runnable
                        public final void run() throws XmlPullParserException, IOException {
                            this.f$0.lambda$null$6$AboutAppActivity(progressDialog, finished, zipFile);
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

    public /* synthetic */ void lambda$null$6$AboutAppActivity(AlertDialog progressDialog, boolean[] finished, File zipFile) throws XmlPullParserException, IOException {
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

    private void addTextView(LinearLayout parent, TextView tv, int textSize, int textColor, CharSequence text, ViewGroup.LayoutParams lp) {
        if (tv == null) {
            return;
        }
        tv.setTextSize(1, textSize);
        tv.setTextColor(textColor);
        tv.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        tv.setText(text);
        parent.addView(tv, lp);
    }
}
