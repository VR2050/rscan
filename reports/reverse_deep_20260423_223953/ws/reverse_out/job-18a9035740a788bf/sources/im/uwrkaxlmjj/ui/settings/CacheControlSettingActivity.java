package im.uwrkaxlmjj.ui.settings;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import com.bjz.comm.net.utils.AppPreferenceUtil;
import im.uwrkaxlmjj.javaBean.fc.FollowedFcListBean;
import im.uwrkaxlmjj.javaBean.fc.HomeFcListBean;
import im.uwrkaxlmjj.javaBean.fc.RecommendFcListBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.dialogs.DialogClearCache;
import im.uwrkaxlmjj.ui.dialogs.DialogCommonList;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.helper.FcDBHelper;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CacheControlSettingActivity extends BaseFragment {
    private long databaseSize = -1;
    private long cacheSize = -1;
    private volatile boolean canceled = false;
    private boolean calculating = true;
    private long documentsSize = -1;
    private long audioSize = -1;
    private long musicSize = -1;
    private long photoSize = -1;
    private long videoSize = -1;
    private long totalSize = -1;
    private boolean[] clear = new boolean[6];

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        this.databaseSize = MessagesStorage.getInstance(this.currentAccount).getDatabaseSize();
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$CacheControlSettingActivity$qG3CiLSzOUS2hqmj902yhezOhqw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onFragmentCreate$1$CacheControlSettingActivity();
            }
        });
        return true;
    }

    public /* synthetic */ void lambda$onFragmentCreate$1$CacheControlSettingActivity() {
        this.cacheSize = getDirectorySize(FileLoader.checkDirectory(4), 0);
        if (this.canceled) {
            return;
        }
        this.photoSize = getDirectorySize(FileLoader.checkDirectory(0), 0);
        if (this.canceled) {
            return;
        }
        this.videoSize = getDirectorySize(FileLoader.checkDirectory(2), 0);
        if (this.canceled) {
            return;
        }
        this.documentsSize = getDirectorySize(FileLoader.checkDirectory(3), 1);
        if (!this.canceled) {
            this.musicSize = getDirectorySize(FileLoader.checkDirectory(3), 2);
            if (this.canceled) {
                return;
            }
            long directorySize = getDirectorySize(FileLoader.checkDirectory(1), 0);
            this.audioSize = directorySize;
            this.totalSize = this.cacheSize + this.videoSize + directorySize + this.photoSize + this.documentsSize + this.musicSize;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$CacheControlSettingActivity$GH9USmlNjZPgkgGke_0e1d9eJEg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$CacheControlSettingActivity();
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$0$CacheControlSettingActivity() {
        this.calculating = false;
        initState();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        this.canceled = true;
    }

    private long getDirectorySize(File dir, int documentsMusicType) {
        if (dir == null || this.canceled) {
            return 0L;
        }
        if (dir.isDirectory()) {
            long size = Utilities.getDirSize(dir.getAbsolutePath(), documentsMusicType);
            return size;
        }
        if (dir.isFile()) {
            long size2 = 0 + dir.length();
            return size2;
        }
        return 0L;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void cleanupFolders() {
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setCanCancel(false);
        progressDialog.show();
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$CacheControlSettingActivity$N0cm4-6oYd-6quOJtrFXfxBG-u4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cleanupFolders$3$CacheControlSettingActivity(progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$cleanupFolders$3$CacheControlSettingActivity(final AlertDialog progressDialog) {
        boolean imagesCleared = false;
        for (int a = 0; a < 6; a++) {
            if (this.clear[a]) {
                int type = -1;
                int documentsMusicType = 0;
                if (a == 0) {
                    type = 0;
                } else if (a == 1) {
                    type = 2;
                } else if (a == 2) {
                    type = 3;
                    documentsMusicType = 1;
                } else if (a == 3) {
                    type = 3;
                    documentsMusicType = 2;
                } else if (a == 4) {
                    type = 1;
                } else if (a == 5) {
                    type = 4;
                }
                if (type != -1) {
                    File file = FileLoader.checkDirectory(type);
                    if (file != null) {
                        Utilities.clearDir(file.getAbsolutePath(), documentsMusicType, Long.MAX_VALUE);
                    }
                    if (type == 4) {
                        AppPreferenceUtil.putString("PublishFcBean", "");
                        FcDBHelper.getInstance().deleteAll(HomeFcListBean.class);
                        FcDBHelper.getInstance().deleteAll(RecommendFcListBean.class);
                        FcDBHelper.getInstance().deleteAll(FollowedFcListBean.class);
                        this.cacheSize = getDirectorySize(FileLoader.checkDirectory(4), documentsMusicType);
                        imagesCleared = true;
                    } else if (type == 1) {
                        this.audioSize = getDirectorySize(FileLoader.checkDirectory(1), documentsMusicType);
                    } else if (type == 3) {
                        if (documentsMusicType == 1) {
                            this.documentsSize = getDirectorySize(FileLoader.checkDirectory(3), documentsMusicType);
                        } else {
                            this.musicSize = getDirectorySize(FileLoader.checkDirectory(3), documentsMusicType);
                        }
                    } else if (type == 0) {
                        imagesCleared = true;
                        this.photoSize = getDirectorySize(FileLoader.checkDirectory(0), documentsMusicType);
                    } else if (type == 2) {
                        this.videoSize = getDirectorySize(FileLoader.checkDirectory(2), documentsMusicType);
                    }
                }
            }
        }
        final boolean imagesClearedFinal = imagesCleared;
        this.totalSize = this.cacheSize + this.videoSize + this.audioSize + this.photoSize + this.documentsSize + this.musicSize;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$CacheControlSettingActivity$VqlFhERLWoEqA41ao8Vd4xF5fD8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$CacheControlSettingActivity(imagesClearedFinal, progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$CacheControlSettingActivity(boolean imagesClearedFinal, AlertDialog progressDialog) {
        if (imagesClearedFinal) {
            ImageLoader.getInstance().clearMemory();
        }
        initState();
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void initListener() {
        this.fragmentView.findViewById(R.attr.rl_cache_period).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.CacheControlSettingActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (CacheControlSettingActivity.this.getParentActivity() == null) {
                    return;
                }
                List<String> arrList = new ArrayList<>();
                arrList.add(LocaleController.formatPluralString("Days", 3));
                arrList.add(LocaleController.formatPluralString("Weeks", 1));
                arrList.add(LocaleController.formatPluralString("Months", 1));
                arrList.add(LocaleController.getString("KeepMediaForever", R.string.KeepMediaForever));
                DialogCommonList dialogCommonList = new DialogCommonList(CacheControlSettingActivity.this.getParentActivity(), arrList, 0, new DialogCommonList.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.settings.CacheControlSettingActivity.1.1
                    @Override // im.uwrkaxlmjj.ui.dialogs.DialogCommonList.RecyclerviewItemClickCallBack
                    public void onRecyclerviewItemClick(int which) {
                        if (which == 0) {
                            SharedConfig.setKeepMedia(3);
                        } else if (which == 1) {
                            SharedConfig.setKeepMedia(0);
                        } else if (which == 2) {
                            SharedConfig.setKeepMedia(1);
                        } else if (which == 3) {
                            SharedConfig.setKeepMedia(2);
                        }
                        CacheControlSettingActivity.this.initState();
                        SharedConfig.checkKeepMedia();
                    }
                });
                dialogCommonList.show();
            }
        });
        this.fragmentView.findViewById(R.attr.rl_clear_cache).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.CacheControlSettingActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (CacheControlSettingActivity.this.totalSize <= 0 || CacheControlSettingActivity.this.getParentActivity() == null) {
                    return;
                }
                final List<CacheInfo> arrList = new ArrayList<>();
                for (int a = 0; a < 6; a++) {
                    long size = 0;
                    CacheInfo cacheInfo = CacheControlSettingActivity.this.new CacheInfo();
                    if (a == 0) {
                        size = CacheControlSettingActivity.this.photoSize;
                    } else if (a == 1) {
                        size = CacheControlSettingActivity.this.videoSize;
                    } else if (a == 2) {
                        size = CacheControlSettingActivity.this.documentsSize;
                    } else if (a == 3) {
                        size = CacheControlSettingActivity.this.musicSize;
                    } else if (a == 4) {
                        size = CacheControlSettingActivity.this.audioSize;
                    } else if (a == 5) {
                        size = CacheControlSettingActivity.this.cacheSize;
                    }
                    if (size <= 0) {
                        CacheControlSettingActivity.this.clear[a] = false;
                    } else {
                        CacheControlSettingActivity.this.clear[a] = true;
                        cacheInfo.setMiIndex(a);
                        cacheInfo.setMlCacheSize(size);
                        arrList.add(cacheInfo);
                    }
                }
                DialogClearCache dialogClearCache = new DialogClearCache(CacheControlSettingActivity.this.getParentActivity(), arrList, new DialogClearCache.CacheClearSelectCallback() { // from class: im.uwrkaxlmjj.ui.settings.CacheControlSettingActivity.2.1
                    @Override // im.uwrkaxlmjj.ui.dialogs.DialogClearCache.CacheClearSelectCallback
                    public void onCacheClearSelect(boolean[] arrBln) {
                        for (int i = 0; i < arrList.size(); i++) {
                            CacheControlSettingActivity.this.clear[((CacheInfo) arrList.get(i)).getMiIndex()] = arrBln[i];
                        }
                        CacheControlSettingActivity.this.cleanupFolders();
                    }
                });
                dialogClearCache.show();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void initState() {
        String value;
        int keepMedia = SharedConfig.keepMedia;
        if (keepMedia == 0) {
            value = LocaleController.formatPluralString("Weeks", 1);
        } else {
            value = keepMedia == 1 ? LocaleController.formatPluralString("Months", 1) : keepMedia == 3 ? LocaleController.formatPluralString("Days", 3) : LocaleController.getString("KeepMediaForever", R.string.KeepMediaForever);
        }
        ((TextView) this.fragmentView.findViewById(R.attr.tv_cache_period)).setText(value);
        TextView textView = (TextView) this.fragmentView.findViewById(R.attr.tv_clear_cache);
        long j = this.totalSize;
        textView.setText(j == 0 ? LocaleController.getString("CacheEmpty", R.string.CacheEmpty) : AndroidUtilities.formatFileSize(j));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("StorageUsage", R.string.StorageUsage));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.settings.CacheControlSettingActivity.3
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    CacheControlSettingActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_setting_cache_control, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initView(context);
        initListener();
        return this.fragmentView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        initState();
    }

    private void initView(Context context) {
        this.fragmentView.findViewById(R.attr.rl_cache_period).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_server_file).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_clear_cache).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    public class CacheInfo {
        private int miIndex;
        private long mlCacheSize;

        public CacheInfo() {
        }

        public long getMlCacheSize() {
            return this.mlCacheSize;
        }

        public void setMlCacheSize(long mlCacheSize) {
            this.mlCacheSize = mlCacheSize;
        }

        public int getMiIndex() {
            return this.miIndex;
        }

        public void setMiIndex(int miIndex) {
            this.miIndex = miIndex;
        }
    }
}
