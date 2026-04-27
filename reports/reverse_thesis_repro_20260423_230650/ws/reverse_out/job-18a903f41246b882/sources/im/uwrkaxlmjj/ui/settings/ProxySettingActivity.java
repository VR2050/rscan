package im.uwrkaxlmjj.ui.settings;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.Switch;
import android.widget.TextView;
import androidx.recyclerview.widget.DefaultItemAnimator;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.king.zxing.util.LogUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestTimeDelegate;
import im.uwrkaxlmjj.ui.ProxySettingsActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
@Deprecated
public class ProxySettingActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private int callsDetailRow;
    private int callsRow;
    private int connectionsHeaderRow;
    private int currentConnectionState;
    private FrameLayout mFrameLayout;
    private ListAdapter mListAdapter;
    private RecyclerListView mListView;
    private Switch mScUseProxy;
    private int proxyAddRow;
    private int proxyDetailRow;
    private int proxyEndRow;
    private int proxyStartRow;
    private int rowCount;
    private int useProxyDetailRow;
    private boolean useProxyForCalls;
    private int useProxyRow;
    private boolean useProxySettings;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString("Proxy", R.string.Proxy));
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setAllowOverlayTitle(true);
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_setting_proxy, (ViewGroup) null, false);
        this.mListView = new RecyclerListView(context);
        this.mListAdapter = new ListAdapter(context);
        ((DefaultItemAnimator) this.mListView.getItemAnimator()).setDelayAnimations(false);
        this.mListView.setVerticalScrollBarEnabled(false);
        this.mListView.setLayoutManager(new LinearLayoutManager(context, 1, false));
        initView();
        initListener();
        return this.fragmentView;
    }

    private void initView() {
        this.mScUseProxy = (Switch) this.fragmentView.findViewById(R.attr.switch_proxy);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_container);
        this.mFrameLayout = frameLayout;
        frameLayout.addView(this.mListView, LayoutHelper.createFrame(-1, -1, 51));
        this.mListView.setAdapter(this.mListAdapter);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        SharedConfig.loadProxyList();
        this.currentConnectionState = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.proxySettingsChanged);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.proxyCheckDone);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.didUpdateConnectionState);
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        this.useProxySettings = preferences.getBoolean("proxy_enabled", false) && !SharedConfig.proxyList.isEmpty();
        this.useProxyForCalls = preferences.getBoolean("proxy_enabled_calls", false);
        updateRows(true);
        return true;
    }

    private void initState() {
        this.mScUseProxy.setChecked(this.useProxySettings);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateRows(boolean notify) {
        ListAdapter listAdapter;
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.useProxyRow = 0;
        int i2 = i + 1;
        this.rowCount = i2;
        this.useProxyDetailRow = i;
        this.rowCount = i2 + 1;
        this.connectionsHeaderRow = i2;
        if (!SharedConfig.proxyList.isEmpty()) {
            int i3 = this.rowCount;
            this.proxyStartRow = i3;
            int size = i3 + SharedConfig.proxyList.size();
            this.rowCount = size;
            this.proxyEndRow = size;
        } else {
            this.proxyStartRow = -1;
            this.proxyEndRow = -1;
        }
        int i4 = this.rowCount;
        int i5 = i4 + 1;
        this.rowCount = i5;
        this.proxyAddRow = i4;
        this.rowCount = i5 + 1;
        this.proxyDetailRow = i5;
        if (SharedConfig.currentProxy == null || SharedConfig.currentProxy.secret.isEmpty()) {
            if (this.callsRow == -1) {
            }
            int i6 = this.rowCount;
            int i7 = i6 + 1;
            this.rowCount = i7;
            this.callsRow = i6;
            this.rowCount = i7 + 1;
            this.callsDetailRow = i7;
        } else {
            if (this.callsRow != -1) {
            }
            this.callsRow = -1;
            this.callsDetailRow = -1;
        }
        checkProxyList();
        if (notify && (listAdapter = this.mListAdapter) != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void checkProxyList() {
        int count = SharedConfig.proxyList.size();
        for (int a = 0; a < count; a++) {
            final SharedConfig.ProxyInfo proxyInfo = SharedConfig.proxyList.get(a);
            if (!proxyInfo.checking && SystemClock.elapsedRealtime() - proxyInfo.availableCheckTime >= 120000) {
                proxyInfo.checking = true;
                proxyInfo.proxyCheckPingId = ConnectionsManager.getInstance(this.currentAccount).checkProxy(proxyInfo.address, proxyInfo.port, proxyInfo.username, proxyInfo.password, proxyInfo.secret, new RequestTimeDelegate() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$ProxySettingActivity$Vy-WlsFrdGxQhyFRxQnmm22sShE
                    @Override // im.uwrkaxlmjj.tgnet.RequestTimeDelegate
                    public final void run(long j) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$ProxySettingActivity$4gYXCIMUV3xqN9hSXmsIfRcukPA
                            @Override // java.lang.Runnable
                            public final void run() {
                                ProxySettingActivity.lambda$null$0(proxyInfo, j);
                            }
                        });
                    }
                });
            }
        }
    }

    static /* synthetic */ void lambda$null$0(SharedConfig.ProxyInfo proxyInfo, long time) {
        proxyInfo.availableCheckTime = SystemClock.elapsedRealtime();
        proxyInfo.checking = false;
        if (time == -1) {
            proxyInfo.available = false;
            proxyInfo.ping = 0L;
        } else {
            proxyInfo.ping = time;
            proxyInfo.available = true;
        }
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxyCheckDone, proxyInfo);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onDialogDismiss(Dialog dialog) {
        DownloadController.getInstance(this.currentAccount).checkAutodownloadSettings();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.mListAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        initState();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.proxySettingsChanged);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.proxyCheckDone);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didUpdateConnectionState);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        RecyclerListView.Holder holder;
        int idx;
        RecyclerListView.Holder holder2;
        if (id == NotificationCenter.proxySettingsChanged) {
            updateRows(true);
            return;
        }
        if (id == NotificationCenter.didUpdateConnectionState) {
            int state = ConnectionsManager.getInstance(account).getConnectionState();
            if (this.currentConnectionState != state) {
                this.currentConnectionState = state;
                if (this.mListView != null && SharedConfig.currentProxy != null && (idx = SharedConfig.proxyList.indexOf(SharedConfig.currentProxy)) >= 0 && (holder2 = (RecyclerListView.Holder) this.mListView.findViewHolderForAdapterPosition(idx)) != null) {
                    TextDetailProxyCell cell = (TextDetailProxyCell) holder2.itemView;
                    cell.updateStatus();
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.proxyCheckDone && this.mListView != null) {
            SharedConfig.ProxyInfo proxyInfo = (SharedConfig.ProxyInfo) args[0];
            int idx2 = SharedConfig.proxyList.indexOf(proxyInfo);
            if (idx2 >= 0 && (holder = (RecyclerListView.Holder) this.mListView.findViewHolderForAdapterPosition(idx2)) != null) {
                TextDetailProxyCell cell2 = (TextDetailProxyCell) holder.itemView;
                cell2.updateStatus();
            }
        }
    }

    private void initListener() {
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.settings.ProxySettingActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    ProxySettingActivity.this.finishFragment();
                }
            }
        });
        this.mScUseProxy.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.ProxySettingActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (SharedConfig.currentProxy == null) {
                    if (!SharedConfig.proxyList.isEmpty()) {
                        SharedConfig.currentProxy = SharedConfig.proxyList.get(0);
                        if (!ProxySettingActivity.this.useProxySettings) {
                            MessagesController.getGlobalMainSettings();
                            SharedPreferences.Editor editor = MessagesController.getGlobalMainSettings().edit();
                            editor.putString("proxy_ip", SharedConfig.currentProxy.address);
                            editor.putString("proxy_pass", SharedConfig.currentProxy.password);
                            editor.putString("proxy_user", SharedConfig.currentProxy.username);
                            editor.putInt("proxy_port", SharedConfig.currentProxy.port);
                            editor.putString("proxy_secret", SharedConfig.currentProxy.secret);
                            editor.commit();
                        }
                    } else {
                        ProxySettingActivity.this.presentFragment(new ProxySettingsActivity());
                        return;
                    }
                }
                ProxySettingActivity.this.useProxySettings = !r0.useProxySettings;
                MessagesController.getGlobalMainSettings();
                ((Switch) view).setChecked(ProxySettingActivity.this.useProxySettings);
                if (!ProxySettingActivity.this.useProxySettings) {
                    ProxySettingActivity.this.useProxyForCalls = false;
                }
                SharedPreferences.Editor editor2 = MessagesController.getGlobalMainSettings().edit();
                editor2.putBoolean("proxy_enabled", ProxySettingActivity.this.useProxySettings);
                editor2.commit();
                ConnectionsManager.setProxySettings(ProxySettingActivity.this.useProxySettings, SharedConfig.currentProxy.address, SharedConfig.currentProxy.port, SharedConfig.currentProxy.username, SharedConfig.currentProxy.password, SharedConfig.currentProxy.secret);
                NotificationCenter.getGlobalInstance().removeObserver(ProxySettingActivity.this, NotificationCenter.proxySettingsChanged);
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged, new Object[0]);
                NotificationCenter.getGlobalInstance().addObserver(ProxySettingActivity.this, NotificationCenter.proxySettingsChanged);
                for (int a = 0; a < SharedConfig.proxyList.size(); a++) {
                    RecyclerListView.Holder holder = (RecyclerListView.Holder) ProxySettingActivity.this.mListView.findViewHolderForAdapterPosition(a);
                    if (holder != null) {
                        TextDetailProxyCell cell = (TextDetailProxyCell) holder.itemView;
                        cell.updateStatus();
                    }
                }
            }
        });
        this.fragmentView.findViewById(R.attr.rl_add_proxy).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.ProxySettingActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                ProxySettingActivity.this.presentFragment(new ProxySettingsActivity());
            }
        });
        this.mListView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.settings.ProxySettingActivity.4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public void onItemClick(View view, int position) {
                SharedConfig.ProxyInfo info = SharedConfig.proxyList.get(position);
                ProxySettingActivity.this.useProxySettings = true;
                SharedPreferences.Editor editor = MessagesController.getGlobalMainSettings().edit();
                editor.putString("proxy_ip", info.address);
                editor.putString("proxy_pass", info.password);
                editor.putString("proxy_user", info.username);
                editor.putInt("proxy_port", info.port);
                editor.putString("proxy_secret", info.secret);
                editor.putBoolean("proxy_enabled", ProxySettingActivity.this.useProxySettings);
                if (!info.secret.isEmpty()) {
                    ProxySettingActivity.this.useProxyForCalls = false;
                    editor.putBoolean("proxy_enabled_calls", false);
                }
                editor.commit();
                SharedConfig.currentProxy = info;
                for (int a = 0; a < SharedConfig.proxyList.size(); a++) {
                    RecyclerListView.Holder holder = (RecyclerListView.Holder) ProxySettingActivity.this.mListView.findViewHolderForAdapterPosition(a);
                    if (holder != null) {
                        TextDetailProxyCell cell = (TextDetailProxyCell) holder.itemView;
                        cell.setChecked(cell.currentInfo == info);
                        cell.updateStatus();
                    }
                }
                ProxySettingActivity.this.updateRows(false);
                ProxySettingActivity.this.mScUseProxy.setChecked(true);
                ConnectionsManager.setProxySettings(ProxySettingActivity.this.useProxySettings, SharedConfig.currentProxy.address, SharedConfig.currentProxy.port, SharedConfig.currentProxy.username, SharedConfig.currentProxy.password, SharedConfig.currentProxy.secret);
            }
        });
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return SharedConfig.proxyList.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                if (position == ProxySettingActivity.this.proxyDetailRow && ProxySettingActivity.this.callsRow == -1) {
                    holder.itemView.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                    return;
                } else {
                    holder.itemView.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                    return;
                }
            }
            if (itemViewType == 1) {
                TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
                textCell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                if (position == ProxySettingActivity.this.proxyAddRow) {
                    textCell.setText(LocaleController.getString("AddProxy", R.string.AddProxy), false);
                    return;
                }
                return;
            }
            if (itemViewType == 2) {
                HeaderCell headerCell = (HeaderCell) holder.itemView;
                if (position == ProxySettingActivity.this.connectionsHeaderRow) {
                    headerCell.setText(LocaleController.getString("ProxyConnections", R.string.ProxyConnections));
                    return;
                }
                return;
            }
            if (itemViewType == 3) {
                TextCheckCell checkCell = (TextCheckCell) holder.itemView;
                if (position == ProxySettingActivity.this.useProxyRow) {
                    checkCell.setTextAndCheck(LocaleController.getString("UseProxySettings", R.string.UseProxySettings), ProxySettingActivity.this.useProxySettings, false);
                    return;
                } else {
                    if (position == ProxySettingActivity.this.callsRow) {
                        checkCell.setTextAndCheck(LocaleController.getString("UseProxyForCalls", R.string.UseProxyForCalls), ProxySettingActivity.this.useProxyForCalls, false);
                        return;
                    }
                    return;
                }
            }
            if (itemViewType == 4) {
                TextInfoPrivacyCell cell = (TextInfoPrivacyCell) holder.itemView;
                if (position == ProxySettingActivity.this.callsDetailRow) {
                    cell.setText(LocaleController.getString("UseProxyForCallsInfo", R.string.UseProxyForCallsInfo));
                    cell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                    return;
                }
                return;
            }
            if (itemViewType == 5) {
                TextDetailProxyCell cell2 = (TextDetailProxyCell) holder.itemView;
                SharedConfig.ProxyInfo info = SharedConfig.proxyList.get(position);
                cell2.setProxy(info);
                cell2.setChecked(SharedConfig.currentProxy == info);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            int viewType = holder.getItemViewType();
            if (viewType == 3) {
                TextCheckCell checkCell = (TextCheckCell) holder.itemView;
                int position = holder.getAdapterPosition();
                if (position == ProxySettingActivity.this.useProxyRow) {
                    checkCell.setChecked(ProxySettingActivity.this.useProxySettings);
                } else if (position == ProxySettingActivity.this.callsRow) {
                    checkCell.setChecked(ProxySettingActivity.this.useProxyForCalls);
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            holder.getAdapterPosition();
            return true;
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
                view = ProxySettingActivity.this.new TextDetailProxyCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return 5;
        }
    }

    public class TextDetailProxyCell extends FrameLayout {
        private Drawable checkDrawable;
        private ImageView checkImageView;
        private int color;
        private SharedConfig.ProxyInfo currentInfo;
        private TextView textView;
        private TextView valueTextView;

        public TextDetailProxyCell(Context context) {
            super(context);
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.textView.setTextSize(1, 16.0f);
            this.textView.setLines(1);
            this.textView.setMaxLines(1);
            this.textView.setSingleLine(true);
            this.textView.setEllipsize(TextUtils.TruncateAt.END);
            this.textView.setGravity((LocaleController.isRTL ? 5 : 3) | 16);
            addView(this.textView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 56 : 21, 10.0f, LocaleController.isRTL ? 21 : 56, 0.0f));
            TextView textView2 = new TextView(context);
            this.valueTextView = textView2;
            textView2.setTextSize(1, 13.0f);
            this.valueTextView.setGravity(LocaleController.isRTL ? 5 : 3);
            this.valueTextView.setLines(1);
            this.valueTextView.setMaxLines(1);
            this.valueTextView.setSingleLine(true);
            this.valueTextView.setCompoundDrawablePadding(AndroidUtilities.dp(6.0f));
            this.valueTextView.setEllipsize(TextUtils.TruncateAt.END);
            this.valueTextView.setPadding(0, 0, 0, 0);
            addView(this.valueTextView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 56 : 21, 35.0f, LocaleController.isRTL ? 21 : 56, 0.0f));
            ImageView imageView = new ImageView(context);
            this.checkImageView = imageView;
            imageView.setImageResource(R.drawable.profile_info);
            this.checkImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3), PorterDuff.Mode.MULTIPLY));
            this.checkImageView.setScaleType(ImageView.ScaleType.CENTER);
            this.checkImageView.setContentDescription(LocaleController.getString("Edit", R.string.Edit));
            addView(this.checkImageView, LayoutHelper.createFrame(48.0f, 48.0f, (LocaleController.isRTL ? 3 : 5) | 48, 8.0f, 8.0f, 8.0f, 0.0f));
            this.checkImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$ProxySettingActivity$TextDetailProxyCell$G6vUmmCA2fG1KPwM1oZZwwGQ7F4
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$0$ProxySettingActivity$TextDetailProxyCell(view);
                }
            });
            setWillNotDraw(false);
        }

        public /* synthetic */ void lambda$new$0$ProxySettingActivity$TextDetailProxyCell(View v) {
            ProxySettingActivity.this.presentFragment(new ProxySettingsActivity(this.currentInfo));
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(64.0f) + 1, 1073741824));
        }

        public void setProxy(SharedConfig.ProxyInfo proxyInfo) {
            this.textView.setText(proxyInfo.address + LogUtils.COLON + proxyInfo.port);
            this.currentInfo = proxyInfo;
        }

        public void updateStatus() {
            String colorKey;
            if (SharedConfig.currentProxy == this.currentInfo && ProxySettingActivity.this.useProxySettings) {
                if (ProxySettingActivity.this.currentConnectionState == 3 || ProxySettingActivity.this.currentConnectionState == 5) {
                    colorKey = Theme.key_windowBackgroundWhiteBlueText6;
                    if (this.currentInfo.ping != 0) {
                        this.valueTextView.setText(LocaleController.getString("Connected", R.string.Connected) + ", " + LocaleController.formatString("Ping", R.string.Ping, Long.valueOf(this.currentInfo.ping)));
                    } else {
                        this.valueTextView.setText(LocaleController.getString("Connected", R.string.Connected));
                    }
                    if (!this.currentInfo.checking && !this.currentInfo.available) {
                        this.currentInfo.availableCheckTime = 0L;
                    }
                } else {
                    colorKey = Theme.key_windowBackgroundWhiteGrayText2;
                    this.valueTextView.setText(LocaleController.getString("Connecting", R.string.Connecting));
                }
            } else if (this.currentInfo.checking) {
                this.valueTextView.setText(LocaleController.getString("Checking", R.string.Checking));
                colorKey = Theme.key_windowBackgroundWhiteGrayText2;
            } else if (this.currentInfo.available) {
                if (this.currentInfo.ping != 0) {
                    this.valueTextView.setText(LocaleController.getString("Available", R.string.Available) + ", " + LocaleController.formatString("Ping", R.string.Ping, Long.valueOf(this.currentInfo.ping)));
                } else {
                    this.valueTextView.setText(LocaleController.getString("Available", R.string.Available));
                }
                colorKey = Theme.key_windowBackgroundWhiteGreenText;
            } else {
                this.valueTextView.setText(LocaleController.getString("Unavailable", R.string.Unavailable));
                colorKey = Theme.key_windowBackgroundWhiteRedText4;
            }
            this.color = Theme.getColor(colorKey);
            this.valueTextView.setTag(colorKey);
            this.valueTextView.setTextColor(this.color);
            Drawable drawable = this.checkDrawable;
            if (drawable != null) {
                drawable.setColorFilter(new PorterDuffColorFilter(this.color, PorterDuff.Mode.MULTIPLY));
            }
        }

        public void setChecked(boolean checked) {
            if (!checked) {
                this.valueTextView.setCompoundDrawablesWithIntrinsicBounds((Drawable) null, (Drawable) null, (Drawable) null, (Drawable) null);
                return;
            }
            if (this.checkDrawable == null) {
                this.checkDrawable = getResources().getDrawable(R.drawable.proxy_check).mutate();
            }
            Drawable drawable = this.checkDrawable;
            if (drawable != null) {
                drawable.setColorFilter(new PorterDuffColorFilter(this.color, PorterDuff.Mode.MULTIPLY));
            }
            if (LocaleController.isRTL) {
                this.valueTextView.setCompoundDrawablesWithIntrinsicBounds((Drawable) null, (Drawable) null, this.checkDrawable, (Drawable) null);
            } else {
                this.valueTextView.setCompoundDrawablesWithIntrinsicBounds(this.checkDrawable, (Drawable) null, (Drawable) null, (Drawable) null);
            }
        }

        public void setValue(CharSequence value) {
            this.valueTextView.setText(value);
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            updateStatus();
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            canvas.drawLine(LocaleController.isRTL ? 0.0f : AndroidUtilities.dp(20.0f), getMeasuredHeight() - 1, getMeasuredWidth() - (LocaleController.isRTL ? AndroidUtilities.dp(20.0f) : 0), getMeasuredHeight() - 1, Theme.dividerPaint);
        }
    }
}
