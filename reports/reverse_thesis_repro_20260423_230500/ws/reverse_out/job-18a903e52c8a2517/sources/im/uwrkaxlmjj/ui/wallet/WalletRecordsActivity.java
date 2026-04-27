package im.uwrkaxlmjj.ui.wallet;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Typeface;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bigkoo.pickerview.listener.OnTimeSelectListener;
import com.blankj.utilcode.util.ColorUtils;
import com.blankj.utilcode.util.SpanUtils;
import com.blankj.utilcode.util.TimeUtils;
import com.library.MyRecyclerViewList;
import com.library.PowerfulStickyDecoration;
import com.library.listener.OnGroupClickListener;
import com.library.listener.PowerGroupListener;
import com.litesuits.orm.db.assit.SQLBuilder;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.listener.OnRefreshLoadMoreListener;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.EmptyCell;
import im.uwrkaxlmjj.ui.components.AppTextView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.dialogs.TimeWheelPickerDialog;
import im.uwrkaxlmjj.ui.hviews.MryLinearLayout;
import im.uwrkaxlmjj.ui.load.SpinKitView;
import im.uwrkaxlmjj.ui.load.SpriteFactory;
import im.uwrkaxlmjj.ui.load.Style;
import im.uwrkaxlmjj.ui.load.sprite.Sprite;
import im.uwrkaxlmjj.ui.utils.number.MoneyUtil;
import im.uwrkaxlmjj.ui.wallet.model.BillRecordResBillListBean;
import im.uwrkaxlmjj.ui.wallet.model.BillRecordsReqBean;
import im.uwrkaxlmjj.ui.wallet.model.BillRecordsResBean;
import im.uwrkaxlmjj.ui.wallet.model.Constants;
import im.uwrkaxlmjj.ui.wallet.utils.AnimationUtils;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletRecordsActivity extends BaseFragment {
    private ListAdapter adapter;
    private AppTextView btn;
    private LinearLayout container;
    private PowerfulStickyDecoration decoration;
    private View emptyDivider;
    private MryLinearLayout emptyLayout;
    private MyRecyclerViewList listView;
    private SpinKitView loadView;
    private SmartRefreshLayout refreshLayout;
    private Date selectDate;
    private LinearLayout selectLayout;
    private LinearLayout tipLayout;
    private TextView tvEmptyIn;
    private TextView tvEmptyOut;
    private TextView tvSelectDate2;
    private TextView tvTips;
    private int currentPage = 1;
    private int pageSize = 20;
    private String selectDateStr = "";
    private boolean end = false;
    private ArrayList<String> dateKeyLis = new ArrayList<>();
    private HashMap<String, BillRecordsResBean> beanMap = new HashMap<>();
    private String tempKey = "";

    static /* synthetic */ int access$208(WalletRecordsActivity x0) {
        int i = x0.currentPage;
        x0.currentPage = i + 1;
        return i;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_wallet_records_layout, (ViewGroup) null);
        initActionBar();
        initViews();
        showLoading();
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordsActivity$t-TWzhhIvVe98NrziNGHBI2lSbo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$createView$0$WalletRecordsActivity();
            }
        }, 1000L);
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$0$WalletRecordsActivity() {
        loadRecords(this.selectDateStr, this.currentPage, this.pageSize, false, true);
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString(R.string.TransactionDetails2));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    WalletRecordsActivity.this.finishFragment();
                }
            }
        });
    }

    private void initViews() {
        this.refreshLayout = (SmartRefreshLayout) this.fragmentView.findViewById(R.attr.refreshLayout);
        this.loadView = (SpinKitView) this.fragmentView.findViewById(R.attr.loadView);
        this.emptyLayout = (MryLinearLayout) this.fragmentView.findViewById(R.attr.emptyLayout);
        this.tipLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.tipLayout);
        this.tvEmptyIn = (TextView) this.fragmentView.findViewById(R.attr.tvEmptyIn);
        this.tvEmptyOut = (TextView) this.fragmentView.findViewById(R.attr.tvEmptyOut);
        this.emptyDivider = this.fragmentView.findViewById(R.attr.emptyDivider);
        this.tvTips = (TextView) this.fragmentView.findViewById(R.attr.tvTips);
        this.btn = (AppTextView) this.fragmentView.findViewById(R.attr.btn);
        this.selectLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.selectLayout);
        this.tvSelectDate2 = (TextView) this.fragmentView.findViewById(R.attr.tvSelectDate2);
        this.container = (LinearLayout) this.fragmentView.findViewById(R.attr.container);
        this.listView = (MyRecyclerViewList) this.fragmentView.findViewById(R.attr.listView);
        this.loadView.setColor(Theme.value_WalletPageBlueTextColor);
        Sprite drawable = SpriteFactory.create(Style.CIRCLE);
        this.loadView.setIndeterminateDrawable(drawable);
        SpanUtils.with(this.tvEmptyIn).append(LocaleController.getString(R.string.IncomeFormat)).append("￥").setTypeface(Typeface.MONOSPACE).append("0.00").create();
        SpanUtils.with(this.tvEmptyOut).append(LocaleController.getString(R.string.ExpenditureFormat)).append("￥").setTypeface(Typeface.MONOSPACE).append("0.00").create();
        this.selectLayout.setBackground(Theme.getSelectorDrawable(false));
        this.btn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordsActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                WalletRecordsActivity.this.showLoading();
                WalletRecordsActivity walletRecordsActivity = WalletRecordsActivity.this;
                walletRecordsActivity.loadRecords(walletRecordsActivity.selectDateStr, WalletRecordsActivity.this.currentPage, WalletRecordsActivity.this.pageSize, false, true);
            }
        });
        rebuildSticky();
        LinearLayoutManager layoutManager = new LinearLayoutManager(getParentActivity());
        this.adapter = new ListAdapter(getParentActivity());
        this.listView.setEmptyView(this.tipLayout);
        this.listView.setLayoutManager(layoutManager);
        this.listView.addItemDecoration(this.decoration);
        this.listView.setAdapter(this.adapter);
        if (this.selectDate == null) {
            Calendar calendar = Calendar.getInstance();
            this.selectDate = calendar.getTime();
        }
        this.selectDateStr = TimeUtils.millis2String(this.selectDate.getTime(), "yyyy-MM");
        this.tempKey = TimeUtils.millis2String(this.selectDate.getTime(), "yyyy/MM");
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordsActivity.3
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public void onItemClick(View view, int position) {
                int section = WalletRecordsActivity.this.adapter.getSectionForPosition(position);
                int row = WalletRecordsActivity.this.adapter.getPositionInSectionForPosition(position);
                if (row >= 0 && section >= 0) {
                    String s = (String) WalletRecordsActivity.this.dateKeyLis.get(section);
                    BillRecordsResBean billRecordsResBean = (BillRecordsResBean) WalletRecordsActivity.this.beanMap.get(s);
                    BillRecordResBillListBean billRecordResBillListBean = billRecordsResBean.getBillList().get(row);
                    if (billRecordResBillListBean.getOrderType() == 1) {
                        WalletRecordWithdrawDetailActivity fragment = new WalletRecordWithdrawDetailActivity();
                        fragment.setBean(billRecordResBillListBean);
                        WalletRecordsActivity.this.presentFragment(fragment);
                    } else if (billRecordResBillListBean.getOrderType() == 3) {
                        WalletRecordWithdrawReturnDetailActivity fragment2 = new WalletRecordWithdrawReturnDetailActivity();
                        fragment2.setBean(billRecordResBillListBean);
                        WalletRecordsActivity.this.presentFragment(fragment2);
                    } else {
                        WalletRecordDetailActivity fragment3 = new WalletRecordDetailActivity();
                        fragment3.setBean(billRecordResBillListBean);
                        WalletRecordsActivity.this.presentFragment(fragment3);
                    }
                }
            }
        });
        this.tvSelectDate2.setText(TimeUtils.millis2String(this.selectDate.getTime(), "yyyy/MM"));
        this.selectLayout.setEnabled(true);
        this.selectLayout.setOnClickListener(new AnonymousClass4());
        this.refreshLayout.setEnableAutoLoadMore(true);
        this.refreshLayout.setOnRefreshLoadMoreListener(new OnRefreshLoadMoreListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordsActivity.5
            @Override // com.scwang.smartrefresh.layout.listener.OnLoadMoreListener
            public void onLoadMore(RefreshLayout refreshLayout) {
                if (WalletRecordsActivity.this.decoration != null) {
                    WalletRecordsActivity.this.decoration.clearCache();
                }
                WalletRecordsActivity walletRecordsActivity = WalletRecordsActivity.this;
                walletRecordsActivity.loadRecords(walletRecordsActivity.selectDateStr, WalletRecordsActivity.this.currentPage, WalletRecordsActivity.this.pageSize, false, true);
            }

            @Override // com.scwang.smartrefresh.layout.listener.OnRefreshListener
            public void onRefresh(RefreshLayout refreshLayout) {
                if (WalletRecordsActivity.this.selectDate != null) {
                    if (WalletRecordsActivity.this.decoration != null) {
                        WalletRecordsActivity.this.decoration.clearCache();
                    }
                    Calendar calendar2 = Calendar.getInstance();
                    calendar2.setTime(WalletRecordsActivity.this.selectDate);
                    calendar2.add(2, 1);
                    if (calendar2.compareTo(Calendar.getInstance()) > 0) {
                        refreshLayout.finishRefresh();
                        return;
                    }
                    WalletRecordsActivity.this.selectDate = calendar2.getTime();
                    WalletRecordsActivity.this.currentPage = 1;
                    WalletRecordsActivity walletRecordsActivity = WalletRecordsActivity.this;
                    walletRecordsActivity.selectDateStr = TimeUtils.millis2String(walletRecordsActivity.selectDate.getTime(), "yyyy-MM");
                    WalletRecordsActivity.this.tvSelectDate2.setText(TimeUtils.millis2String(WalletRecordsActivity.this.selectDate.getTime(), "yyyy/MM"));
                    WalletRecordsActivity walletRecordsActivity2 = WalletRecordsActivity.this;
                    walletRecordsActivity2.tempKey = TimeUtils.millis2String(walletRecordsActivity2.selectDate.getTime(), "yyyy/MM");
                    WalletRecordsActivity walletRecordsActivity3 = WalletRecordsActivity.this;
                    walletRecordsActivity3.loadRecords(walletRecordsActivity3.selectDateStr, WalletRecordsActivity.this.currentPage, WalletRecordsActivity.this.pageSize, true, false);
                }
            }
        });
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.wallet.WalletRecordsActivity$4, reason: invalid class name */
    class AnonymousClass4 implements View.OnClickListener {
        AnonymousClass4() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            TimeWheelPickerDialog.Builder builder = TimeWheelPickerDialog.getDefaultBuilder(WalletRecordsActivity.this.getParentActivity(), new OnTimeSelectListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordsActivity$4$iAUxJVn7hkBPDjz0y_bFmcKCjQo
                @Override // com.bigkoo.pickerview.listener.OnTimeSelectListener
                public final void onTimeSelect(Date date, View view2) {
                    this.f$0.lambda$onClick$0$WalletRecordsActivity$4(date, view2);
                }
            });
            if (WalletRecordsActivity.this.selectDate != null) {
                Calendar calendar = Calendar.getInstance();
                calendar.setTime(WalletRecordsActivity.this.selectDate);
                builder.setDate(calendar);
            } else {
                builder.setDate(Calendar.getInstance());
            }
            builder.setType(new boolean[]{true, true, false, false, false, false});
            WalletRecordsActivity.this.showDialog(builder.build());
        }

        public /* synthetic */ void lambda$onClick$0$WalletRecordsActivity$4(Date date, View v) {
            WalletRecordsActivity.this.selectDate = date;
            String selectStr = TimeUtils.millis2String(WalletRecordsActivity.this.selectDate.getTime(), "yyyy-MM");
            if (!WalletRecordsActivity.this.selectDateStr.equals(selectStr)) {
                WalletRecordsActivity.this.selectDateStr = selectStr;
                WalletRecordsActivity.this.currentPage = 1;
                WalletRecordsActivity.this.tvSelectDate2.setText(TimeUtils.millis2String(WalletRecordsActivity.this.selectDate.getTime(), "yyyy/MM"));
                WalletRecordsActivity walletRecordsActivity = WalletRecordsActivity.this;
                walletRecordsActivity.tempKey = TimeUtils.millis2String(walletRecordsActivity.selectDate.getTime(), "yyyy/MM");
                if (WalletRecordsActivity.this.decoration != null) {
                    WalletRecordsActivity.this.decoration.clearCache();
                }
                WalletRecordsActivity walletRecordsActivity2 = WalletRecordsActivity.this;
                walletRecordsActivity2.loadRecordsBySelected(walletRecordsActivity2.selectDateStr, WalletRecordsActivity.this.currentPage, WalletRecordsActivity.this.pageSize);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void rebuildSticky() {
        PowerGroupListener listener = new PowerGroupListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordsActivity.6
            @Override // com.library.listener.GroupListener
            public String getGroupName(int position) {
                return WalletRecordsActivity.this.adapter.getLetter(position);
            }

            @Override // com.library.listener.PowerGroupListener
            public View getGroupView(int position) {
                String in;
                String out;
                View view = LayoutInflater.from(WalletRecordsActivity.this.getParentActivity()).inflate(R.layout.item_wallet_record_header_layout, (ViewGroup) null, false);
                view.setVisibility(0);
                int section = WalletRecordsActivity.this.adapter.getSectionForPosition(position);
                if (section != -1) {
                    String s = (String) WalletRecordsActivity.this.dateKeyLis.get(section);
                    BillRecordsResBean billRecordsResBean = (BillRecordsResBean) WalletRecordsActivity.this.beanMap.get(s);
                    TextView tvSelectDate = (TextView) view.findViewById(R.attr.tvSelectDate);
                    TextView tvIn = (TextView) view.findViewById(R.attr.tvIn);
                    TextView tvOut = (TextView) view.findViewById(R.attr.tvOut);
                    tvSelectDate.setText(s);
                    if (billRecordsResBean == null) {
                        SpanUtils.with(tvIn).append(LocaleController.getString(R.string.IncomeFormat)).append("￥").setTypeface(Typeface.MONOSPACE).append("0.00").create();
                        SpanUtils.with(tvOut).append(LocaleController.getString(R.string.ExpenditureFormat)).append("￥").setTypeface(Typeface.MONOSPACE).append("0.00").create();
                    } else {
                        String in2 = billRecordsResBean.getStatistics().getIncomeAmount() + "";
                        if (TextUtils.isEmpty(in2)) {
                            in = "0.00";
                        } else {
                            in = MoneyUtil.formatToString(new BigDecimal(in2).divide(new BigDecimal("100")).toString(), 2);
                        }
                        SpanUtils.with(tvIn).append(LocaleController.getString(R.string.IncomeFormat)).append("￥").setTypeface(Typeface.MONOSPACE).append(in).create();
                        String out2 = billRecordsResBean.getStatistics().getExpenditureAmount() + "";
                        if (TextUtils.isEmpty(out2)) {
                            out = "0.00";
                        } else {
                            out = MoneyUtil.formatToString(new BigDecimal(out2).divide(new BigDecimal("100")).toString(), 2);
                        }
                        SpanUtils.with(tvOut).append(LocaleController.getString(R.string.ExpenditureFormat)).append("￥").setTypeface(Typeface.MONOSPACE).append(out).create();
                    }
                }
                return view;
            }
        };
        this.decoration = PowerfulStickyDecoration.Builder.init(listener).setCacheEnable(false).setGroupHeight(AndroidUtilities.dp(62.0f)).setGroupBackground(ColorUtils.getColor(R.color.window_background_gray)).setOnClickListener(new AnonymousClass7()).build();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.wallet.WalletRecordsActivity$7, reason: invalid class name */
    class AnonymousClass7 implements OnGroupClickListener {
        AnonymousClass7() {
        }

        @Override // com.library.listener.OnGroupClickListener
        public void onClick(int position, int id) {
            if (id != -1) {
                TimeWheelPickerDialog.Builder builder = TimeWheelPickerDialog.getDefaultBuilder(WalletRecordsActivity.this.getParentActivity(), new OnTimeSelectListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordsActivity$7$IyfhUY6lCPv2-vu_7BibWltczBE
                    @Override // com.bigkoo.pickerview.listener.OnTimeSelectListener
                    public final void onTimeSelect(Date date, View view) {
                        this.f$0.lambda$onClick$0$WalletRecordsActivity$7(date, view);
                    }
                });
                if (WalletRecordsActivity.this.selectDate != null) {
                    Calendar calendar = Calendar.getInstance();
                    calendar.setTime(WalletRecordsActivity.this.selectDate);
                    builder.setDate(calendar);
                } else {
                    builder.setDate(Calendar.getInstance());
                }
                builder.setType(new boolean[]{true, true, false, false, false, false});
                WalletRecordsActivity.this.showDialog(builder.build());
            }
        }

        public /* synthetic */ void lambda$onClick$0$WalletRecordsActivity$7(Date date, View v) {
            WalletRecordsActivity.this.selectDate = date;
            String selectStr = TimeUtils.millis2String(WalletRecordsActivity.this.selectDate.getTime(), "yyyy-MM");
            if (!WalletRecordsActivity.this.selectDateStr.equals(selectStr)) {
                WalletRecordsActivity.this.selectDateStr = selectStr;
                WalletRecordsActivity.this.currentPage = 1;
                WalletRecordsActivity.this.tvSelectDate2.setText(TimeUtils.millis2String(WalletRecordsActivity.this.selectDate.getTime(), "yyyy/MM"));
                WalletRecordsActivity walletRecordsActivity = WalletRecordsActivity.this;
                walletRecordsActivity.tempKey = TimeUtils.millis2String(walletRecordsActivity.selectDate.getTime(), "yyyy/MM");
                if (WalletRecordsActivity.this.decoration != null) {
                    WalletRecordsActivity.this.decoration.clearCache();
                }
                WalletRecordsActivity walletRecordsActivity2 = WalletRecordsActivity.this;
                walletRecordsActivity2.loadRecordsBySelected(walletRecordsActivity2.selectDateStr, WalletRecordsActivity.this.currentPage, WalletRecordsActivity.this.pageSize);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showError() {
        this.tipLayout.setVisibility(0);
        this.selectLayout.setVisibility(4);
        this.emptyDivider.setVisibility(4);
        this.emptyLayout.setBackgroundResource(R.color.window_background_white);
        this.emptyLayout.setBorderWidth(AndroidUtilities.dp(0.5f));
        AnimationUtils.executeAlphaScaleDisplayAnimation(this.tipLayout);
        this.btn.setVisibility(0);
        this.tvTips.setText(LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater));
        this.tvTips.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
        this.btn.setText(LocaleController.getString(R.string.Refresh));
        this.loadView.setVisibility(8);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showLoading() {
        this.tipLayout.setVisibility(0);
        this.selectLayout.setVisibility(4);
        this.emptyLayout.setBackgroundResource(R.color.transparent);
        this.emptyLayout.setBorderWidth(0);
        this.emptyDivider.setVisibility(8);
        this.tvTips.setText(LocaleController.getString(R.string.NowLoading));
        this.loadView.setVisibility(0);
        this.btn.setVisibility(8);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showEmpty() {
        this.tipLayout.setVisibility(0);
        this.selectLayout.setVisibility(0);
        this.emptyDivider.setVisibility(0);
        this.emptyLayout.setBackgroundResource(R.color.window_background_white);
        this.emptyLayout.setBorderWidth(AndroidUtilities.dp(0.5f));
        this.tvTips.setText(LocaleController.getString(R.string.NoNewBill));
        this.loadView.setVisibility(8);
        this.btn.setVisibility(8);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Type inference failed for: r0v0, types: [T, im.uwrkaxlmjj.ui.wallet.model.BillRecordsReqBean] */
    public void loadRecords(String date, int page, int pageSize, final boolean refresh, boolean loadMore) {
        ?? billRecordsReqBean = new BillRecordsReqBean();
        billRecordsReqBean.setBusinessKey(Constants.KEY_BALANCE_LIST);
        billRecordsReqBean.setUserId(getUserConfig().clientUserId);
        billRecordsReqBean.setPageNum(page);
        billRecordsReqBean.setPageSize(pageSize);
        billRecordsReqBean.setDate(date);
        TLRPCWallet.TL_paymentTrans<BillRecordsReqBean> req = new TLRPCWallet.TL_paymentTrans<>();
        req.requestModel = billRecordsReqBean;
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordsActivity$UctzR7yla28eTgLFVcWiY3pM_-U
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadRecords$1$WalletRecordsActivity(refresh, tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$loadRecords$1$WalletRecordsActivity(final boolean refresh, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordsActivity.8
            @Override // java.lang.Runnable
            public void run() {
                if (error != null) {
                    WalletRecordsActivity.this.showError();
                    if (WalletRecordsActivity.this.adapter != null) {
                        WalletRecordsActivity.this.adapter.notifyDataSetChanged();
                        return;
                    }
                    return;
                }
                TLObject tLObject = response;
                if (tLObject instanceof TLRPCWallet.TL_paymentTransResult) {
                    TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) tLObject;
                    TLApiModel parse = TLJsonResolve.parse3(result.data, BillRecordsResBean.class);
                    if (!parse.isSuccess()) {
                        WalletRecordsActivity.this.showError();
                        if (WalletRecordsActivity.this.adapter != null) {
                            WalletRecordsActivity.this.adapter.notifyDataSetChanged();
                            return;
                        }
                        return;
                    }
                    if (refresh) {
                        WalletRecordsActivity.this.refreshLayout.finishRefresh();
                        WalletRecordsActivity.this.dateKeyLis.clear();
                        WalletRecordsActivity.this.beanMap.clear();
                        WalletRecordsActivity.this.listView.removeItemDecoration(WalletRecordsActivity.this.decoration);
                        WalletRecordsActivity.this.rebuildSticky();
                        WalletRecordsActivity.this.listView.addItemDecoration(WalletRecordsActivity.this.decoration);
                    } else {
                        WalletRecordsActivity.this.refreshLayout.finishLoadMore();
                    }
                    WalletRecordsActivity.access$208(WalletRecordsActivity.this);
                    if (parse.modelList != null && !parse.modelList.isEmpty()) {
                        WalletRecordsActivity.this.handleData(parse.modelList);
                    }
                    WalletRecordsActivity.this.showEmpty();
                    if (WalletRecordsActivity.this.adapter != null) {
                        WalletRecordsActivity.this.adapter.notifyDataSetChanged();
                    }
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Type inference failed for: r0v0, types: [T, im.uwrkaxlmjj.ui.wallet.model.BillRecordsReqBean] */
    public void loadRecordsBySelected(String date, int page, int pageSize) {
        ?? billRecordsReqBean = new BillRecordsReqBean();
        billRecordsReqBean.setBusinessKey(Constants.KEY_BALANCE_LIST);
        billRecordsReqBean.setUserId(getUserConfig().clientUserId);
        billRecordsReqBean.setPageNum(page);
        billRecordsReqBean.setPageSize(pageSize);
        billRecordsReqBean.setDate(date);
        TLRPCWallet.TL_paymentTrans<BillRecordsReqBean> req = new TLRPCWallet.TL_paymentTrans<>();
        req.requestModel = billRecordsReqBean;
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordsActivity$NgMcKLlvr5YSB3si3lxZ6BokiLw
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadRecordsBySelected$2$WalletRecordsActivity(progressDialog, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletRecordsActivity$MDRiDBXzKaLGXf-KAx5XdbficjQ
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$loadRecordsBySelected$3$WalletRecordsActivity(reqId, dialogInterface);
            }
        });
        showDialog(progressDialog);
    }

    public /* synthetic */ void lambda$loadRecordsBySelected$2$WalletRecordsActivity(final AlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletRecordsActivity.9
            @Override // java.lang.Runnable
            public void run() {
                progressDialog.dismiss();
                if (error != null) {
                    WalletRecordsActivity.this.showError();
                    if (WalletRecordsActivity.this.adapter != null) {
                        WalletRecordsActivity.this.adapter.notifyDataSetChanged();
                        return;
                    }
                    return;
                }
                TLObject tLObject = response;
                if (tLObject instanceof TLRPCWallet.TL_paymentTransResult) {
                    TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) tLObject;
                    TLApiModel parse = TLJsonResolve.parse3(result.data, BillRecordsResBean.class);
                    if (parse.isSuccess()) {
                        WalletRecordsActivity.this.refreshLayout.finishRefresh();
                        WalletRecordsActivity.this.dateKeyLis.clear();
                        WalletRecordsActivity.this.beanMap.clear();
                        WalletRecordsActivity.this.listView.removeItemDecoration(WalletRecordsActivity.this.decoration);
                        WalletRecordsActivity.this.rebuildSticky();
                        WalletRecordsActivity.this.listView.addItemDecoration(WalletRecordsActivity.this.decoration);
                        WalletRecordsActivity.access$208(WalletRecordsActivity.this);
                        if (parse.modelList != null && !parse.modelList.isEmpty()) {
                            WalletRecordsActivity.this.handleData(parse.modelList);
                        }
                        WalletRecordsActivity.this.showEmpty();
                    } else {
                        WalletRecordsActivity.this.showError();
                    }
                    if (WalletRecordsActivity.this.adapter != null) {
                        WalletRecordsActivity.this.adapter.notifyDataSetChanged();
                    }
                }
            }
        });
    }

    public /* synthetic */ void lambda$loadRecordsBySelected$3$WalletRecordsActivity(int reqId, DialogInterface dialog) {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequest(reqId, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void handleData(List<BillRecordsResBean> modelList) {
        int count = 0;
        for (int i = 0; i < modelList.size(); i++) {
            BillRecordsResBean bean = modelList.get(i);
            BillRecordsResBean billRecordsResBean = this.beanMap.get(bean.getDateTime());
            if (billRecordsResBean == null) {
                fillKeys(bean.getDateTime());
                this.dateKeyLis.add(bean.getDateTime());
                this.beanMap.put(bean.getDateTime(), bean);
            } else {
                billRecordsResBean.getBillList().addAll(bean.getBillList());
            }
            count += bean.getBillList().size();
        }
        int i2 = this.pageSize;
        if (count < i2) {
            this.refreshLayout.setEnableLoadMore(false);
        }
    }

    private void fillKeys(String dateKey) {
        BillRecordsResBean billRecordsResBean = this.beanMap.get(this.tempKey);
        if (billRecordsResBean == null && !this.tempKey.equals(dateKey)) {
            this.dateKeyLis.add(this.tempKey);
        }
        Long mon = im.uwrkaxlmjj.ui.utils.number.TimeUtils.getTimeLong("yyyy/MM", dateKey);
        Long tempMon = im.uwrkaxlmjj.ui.utils.number.TimeUtils.getTimeLong("yyyy/MM", this.tempKey);
        Calendar current = Calendar.getInstance();
        current.setTimeInMillis(mon.longValue());
        Calendar temp = Calendar.getInstance();
        temp.setTimeInMillis(tempMon.longValue());
        int i = 1;
        int tempYear = temp.get(1);
        int currentYear = current.get(1);
        int tempMonth = temp.get(2) + 1;
        int currentMonth = current.get(2) + 1;
        int i2 = 1;
        while (i2 < (((tempYear - currentYear) * 12) + tempMonth) - currentMonth) {
            current.add(2, i);
            this.dateKeyLis.add(TimeUtils.millis2String(current.getTime().getTime(), "yyyy/MM"));
            i2++;
            tempYear = tempYear;
            i = 1;
        }
        this.tempKey = dateKey;
    }

    private class ListAdapter extends RecyclerListView.SectionsAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 1) {
                view = new EmptyCell(this.mContext, AndroidUtilities.dp(12.0f));
            } else if (viewType == 2) {
                view = LayoutInflater.from(this.mContext).inflate(R.layout.item_wallet_balance_record_empty_layout, parent, false);
            } else {
                view = LayoutInflater.from(this.mContext).inflate(R.layout.item_wallet_balance_record_layout, parent, false);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public String getLetter(int position) {
            int section = getSectionForPosition(position);
            if (section == -1) {
                section = WalletRecordsActivity.this.dateKeyLis.size() - 1;
            }
            if (section >= 0 && section < WalletRecordsActivity.this.dateKeyLis.size()) {
                return (String) WalletRecordsActivity.this.dateKeyLis.get(section);
            }
            return "";
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public int getPositionForScrollProgress(float progress) {
            return 0;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getSectionCount() {
            if (WalletRecordsActivity.this.dateKeyLis != null) {
                int count = 0 + WalletRecordsActivity.this.dateKeyLis.size();
                return count;
            }
            return 0;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getCountForSection(int section) {
            String s = (String) WalletRecordsActivity.this.dateKeyLis.get(section);
            BillRecordsResBean billRecordsResBean = (BillRecordsResBean) WalletRecordsActivity.this.beanMap.get(s);
            if (billRecordsResBean != null && billRecordsResBean.getBillList().size() != 0) {
                return billRecordsResBean.getBillList().size() + 1;
            }
            return 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public boolean isEnabled(int section, int row) {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getItemViewType(int section, int position) {
            String s = (String) WalletRecordsActivity.this.dateKeyLis.get(section);
            BillRecordsResBean billRecordsResBean = (BillRecordsResBean) WalletRecordsActivity.this.beanMap.get(s);
            if (billRecordsResBean == null || billRecordsResBean.getBillList() == null || billRecordsResBean.getBillList().size() == 0) {
                return 2;
            }
            if (position == billRecordsResBean.getBillList().size()) {
                return 1;
            }
            return 0;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public Object getItem(int section, int position) {
            String s = (String) WalletRecordsActivity.this.dateKeyLis.get(section);
            BillRecordsResBean billRecordsResBean = (BillRecordsResBean) WalletRecordsActivity.this.beanMap.get(s);
            if (billRecordsResBean.getBillList() == null || billRecordsResBean.getBillList().size() == 0) {
                return null;
            }
            return billRecordsResBean.getBillList().get(position);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
            String withdrawAmount;
            int type = holder.getItemViewType();
            if (type == 0) {
                ConstraintLayout container = (ConstraintLayout) holder.itemView.findViewById(R.attr.container);
                ImageView ivIcon = (ImageView) holder.itemView.findViewById(R.attr.ivIcon);
                TextView tvTitle = (TextView) holder.itemView.findViewById(R.attr.tvTitle);
                TextView tvTime = (TextView) holder.itemView.findViewById(R.attr.tvTime);
                TextView tvAmount = (TextView) holder.itemView.findViewById(R.attr.tvAmount);
                TextView tvBalance = (TextView) holder.itemView.findViewById(R.attr.tvBalance);
                View divider = holder.itemView.findViewById(R.attr.divider);
                if (position == getCountForSection(section) - 2) {
                    divider.setVisibility(8);
                    container.setBackgroundResource(R.drawable.cell_bottom_selector);
                } else {
                    divider.setVisibility(0);
                    container.setBackgroundResource(R.drawable.cell_middle_selector);
                }
                String s = (String) WalletRecordsActivity.this.dateKeyLis.get(section);
                BillRecordsResBean billRecordsResBean = (BillRecordsResBean) WalletRecordsActivity.this.beanMap.get(s);
                BillRecordResBillListBean billRecordResBillListBean = billRecordsResBean.getBillList().get(position);
                ivIcon.setImageResource(billRecordResBillListBean.getTypeIcon());
                tvTitle.setText(WalletRecordsActivity.this.getTitle(billRecordResBillListBean));
                String createTime = billRecordResBillListBean.getCreateTime();
                if (!TextUtils.isEmpty(createTime)) {
                    createTime = im.uwrkaxlmjj.ui.utils.number.TimeUtils.getTimeLocalString("yyyy-MM-dd HH:mm:ss", createTime, "HH:mm:ss dd/MM/yy");
                }
                tvTime.setText(createTime);
                if (billRecordResBillListBean.getServiceCharge() != 0) {
                    withdrawAmount = new BigDecimal(billRecordResBillListBean.getAmount() + "").add(new BigDecimal(billRecordResBillListBean.getServiceCharge() + "")).divide(new BigDecimal("100")).toString();
                } else {
                    withdrawAmount = new BigDecimal(billRecordResBillListBean.getAmount() + "").divide(new BigDecimal("100")).toString();
                }
                int orderType = billRecordResBillListBean.getOrderType();
                if (WalletRecordsActivity.this.getAddRender(orderType)) {
                    tvAmount.setTextColor(ColorUtils.getColor(R.color.text_amount_add_color));
                } else {
                    tvAmount.setTextColor(ColorUtils.getColor(R.color.text_secondary_color));
                }
                SpanUtils.with(tvAmount).append(billRecordResBillListBean.getDp()).append("￥").setTypeface(Typeface.MONOSPACE).append(MoneyUtil.formatToString(withdrawAmount, 2)).create();
                SpanUtils span = SpanUtils.with(tvBalance);
                if (billRecordResBillListBean.getOrderType() == 7) {
                    tvBalance.setVisibility(8);
                    span.append(LocaleController.getString(R.string.Refunded));
                    span.create();
                    return;
                }
                if (billRecordResBillListBean.getOrderType() == 3) {
                    tvBalance.setVisibility(8);
                    span.append(LocaleController.getString(R.string.WithdrawalFailure));
                    span.create();
                } else {
                    if (billRecordResBillListBean.getOrderType() == 12) {
                        tvBalance.setVisibility(8);
                        span.append(LocaleController.getString(R.string.Refunded));
                        if (!TextUtils.isEmpty(billRecordResBillListBean.getGroupsNumber())) {
                            String rAmount = billRecordResBillListBean.getRefundAmount();
                            if (!TextUtils.isEmpty(rAmount)) {
                                span.append(SQLBuilder.PARENTHESES_LEFT).append("￥").setTypeface(Typeface.MONOSPACE).append(MoneyUtil.formatToString(new BigDecimal(rAmount).divide(new BigDecimal("100")).toString(), 2)).append(SQLBuilder.PARENTHESES_RIGHT);
                            }
                        }
                        span.create();
                        return;
                    }
                    tvBalance.setVisibility(8);
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public View getSectionHeaderView(int section, View view) {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean getAddRender(int type) {
        if (type == 0 || type == 5 || type == 8 || type == 13 || type == 21 || type == 19 || type == 27) {
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String getTitle(BillRecordResBillListBean bean) {
        int orderType = bean.getOrderType();
        if (orderType == 0) {
            String channel = getChannel(bean);
            return String.format(LocaleController.getString(R.string.TopUpFrom), channel);
        }
        if (orderType == 1) {
            String channel2 = getChannel(bean);
            return String.format(LocaleController.getString(R.string.WithdrawalTo), channel2);
        }
        if (orderType == 3) {
            String channel3 = getChannel(bean);
            return String.format(LocaleController.getString(R.string.WithdrawalFailureRefund), channel3);
        }
        if (orderType != 21) {
            switch (orderType) {
                case 5:
                    String targetUserStr = getTargetUserStr(bean);
                    return String.format(LocaleController.getString(R.string.TransferFromSomebody), targetUserStr);
                case 6:
                    String targetUserStr2 = getTargetUserStr(bean);
                    return String.format(LocaleController.getString(R.string.TransferToSombody2), targetUserStr2);
                case 7:
                    String targetUserStr3 = getTargetUserStr(bean);
                    return String.format(LocaleController.getString(R.string.TransferRefundFromSomebody), targetUserStr3);
                case 8:
                    String targetStr = getRedPacketTargetStr(bean);
                    return String.format(LocaleController.getString(R.string.RedPacketFromSomebody), targetStr);
                case 9:
                    String targetUserStr4 = getTargetUserStr(bean);
                    return String.format(LocaleController.getString(R.string.RedPacketToSomebody), targetUserStr4);
                case 10:
                    String targetStr2 = getGroupTargetStr(bean);
                    return String.format(LocaleController.getString(R.string.RedPacketToSomebody), targetStr2);
                case 11:
                    String targetStr3 = getGroupTargetStr(bean);
                    return String.format(LocaleController.getString(R.string.RedPacketToSomebody), targetStr3);
                case 12:
                    String targetStr4 = getRedPacketTargetStr(bean);
                    return String.format(LocaleController.getString(R.string.RedPacketRefundFromSomebody), targetStr4);
                case 13:
                    break;
                default:
                    switch (orderType) {
                        case 25:
                            return LocaleController.getString(R.string.BackOfficeAccount);
                        case 26:
                            String targetUserStr5 = getTargetUserStr(bean);
                            return String.format(LocaleController.getString(R.string.LiveRewardToFormat), targetUserStr5);
                        case 27:
                            String targetUserStr6 = getTargetUserStr(bean);
                            return String.format(LocaleController.getString(R.string.LiveRewardFromFormat), targetUserStr6);
                        default:
                            return LocaleController.getString(R.string.UnKnown);
                    }
            }
        }
        return LocaleController.getString(R.string.BackstageAccount);
    }

    private String getChannel(BillRecordResBillListBean bean) {
        if (TextUtils.isEmpty(bean.getSubInstitutionName())) {
            return "";
        }
        StringBuilder builder = new StringBuilder(bean.getSubInstitutionName());
        return builder.toString();
    }

    private String getTargetUserStr(BillRecordResBillListBean bean) {
        if (TextUtils.isEmpty(bean.getEffectUserId())) {
            return "";
        }
        int targetId = Integer.parseInt(bean.getEffectUserId());
        TLRPC.User user = getMessagesController().getUser(Integer.valueOf(targetId));
        if (user != null) {
            String target = user.first_name;
            return target;
        }
        if (bean.getEffectUserName() == null) {
            return "";
        }
        String target2 = bean.getEffectUserName();
        return target2;
    }

    private String getGroupTargetStr(BillRecordResBillListBean bean) {
        if (TextUtils.isEmpty(bean.getGroupsNumber())) {
            return "";
        }
        int targetId = Integer.parseInt(bean.getGroupsNumber());
        TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(targetId));
        if (chat != null) {
            String targetStr = chat.title;
            return targetStr;
        }
        if (bean.getGroupsName() == null) {
            return "";
        }
        String targetStr2 = bean.getGroupsName();
        return targetStr2;
    }

    private String getRedPacketTargetStr(BillRecordResBillListBean bean) {
        String targetStr = getGroupTargetStr(bean);
        if (TextUtils.isEmpty(targetStr)) {
            return getTargetUserStr(bean);
        }
        return targetStr;
    }
}
