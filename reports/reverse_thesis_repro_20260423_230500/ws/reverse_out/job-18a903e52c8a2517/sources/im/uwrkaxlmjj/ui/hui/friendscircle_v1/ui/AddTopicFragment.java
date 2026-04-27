package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.RespTopicBean;
import com.bjz.comm.net.bean.RespTopicTypeBean;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.utils.RxHelper;
import com.blankj.utilcode.util.SpanUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.utils.DrawableUtils;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.fragments.BaseFmts;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import io.reactivex.Observable;
import io.reactivex.functions.Consumer;
import java.util.HashMap;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AddTopicFragment extends BaseFmts {
    private static final String TAG = "AddTopicFragment";
    private final String TOPICTYPEID = "TOPICTYPEID";
    private String TopicName = "";
    private long TopicTypeID;
    private HashMap<String, RespTopicBean.Item> cacheSelectedHashmap;
    private FrameLayout frame_container;
    private GridLayoutManager gridLayoutManager;
    private RecyclerListView listView;
    private MyAdapter myAdapter;
    private List<RespTopicBean.Item> respTopicBeans;

    public AddTopicFragment(RespTopicTypeBean TopicTypes, HashMap<String, RespTopicBean.Item> cacheSelectedHashmap) {
        this.cacheSelectedHashmap = cacheSelectedHashmap;
        Bundle args = new Bundle();
        args.putLong("TOPICTYPEID", TopicTypes.TopicTypeID);
        setArguments(args);
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.TopicTypeID = getArguments().getLong("TOPICTYPEID");
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        this.fragmentView = inflater.inflate(R.layout.fragment_fc_add_topic, (ViewGroup) null);
        this.frame_container = (FrameLayout) this.fragmentView.findViewById(R.attr.frame_container);
        RecyclerListView recyclerListView = (RecyclerListView) this.fragmentView.findViewById(R.attr.listview);
        this.listView = recyclerListView;
        recyclerListView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView2 = this.listView;
        GridLayoutManager gridLayoutManager = new GridLayoutManager(this.context, 2);
        this.gridLayoutManager = gridLayoutManager;
        recyclerListView2.setLayoutManager(gridLayoutManager);
        RecyclerListView recyclerListView3 = this.listView;
        MyAdapter myAdapter = new MyAdapter(this.context);
        this.myAdapter = myAdapter;
        recyclerListView3.setAdapter(myAdapter);
        this.myAdapter.emptyAttachView(this.frame_container);
        this.myAdapter.showLoading();
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AddTopicFragment$CygoQ1jL9Bs1rXp8TJZjeuYELnI
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$onCreateView$0$AddTopicFragment(view, i);
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$onCreateView$0$AddTopicFragment(View view, int position) {
        RespTopicBean.Item selectedtopic = this.respTopicBeans.get(position);
        String key = selectedtopic.ID + "" + selectedtopic.TypeID;
        if (this.cacheSelectedHashmap.get(key) == null) {
            if (this.cacheSelectedHashmap.size() >= 3) {
                FcToastUtils.show((CharSequence) LocaleController.getString("selcetthreetopic", R.string.selcetthreetopic));
                return;
            }
            this.cacheSelectedHashmap.put(key, selectedtopic);
            getAccountInstance().getNotificationCenter();
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.selectedTopicSuccess, new Object[0]);
            return;
        }
        this.cacheSelectedHashmap.remove(key);
        getAccountInstance().getNotificationCenter();
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.selectedTopicSuccess, new Object[0]);
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void lazyLoadData() {
        super.lazyLoadData();
        getTopics(0);
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void onVisible() {
        super.onVisible();
    }

    private class MyAdapter extends PageSelectionAdapter<RespTopicBean.Item, PageHolder> {
        public MyAdapter(Context context) {
            super(context);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public PageHolder onCreateViewHolderForChild(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(AddTopicFragment.this.context).inflate(R.layout.item_fc_topic, parent, false);
            return new PageHolder(view);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public void onBindViewHolderForChild(PageHolder holder, int position, RespTopicBean.Item item) {
            RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(70.0f));
            if (position % 2 == 0) {
                layoutParams.topMargin = AndroidUtilities.dp(15.0f);
                layoutParams.leftMargin = AndroidUtilities.dp(15.0f);
                layoutParams.rightMargin = AndroidUtilities.dp(10.0f);
            } else {
                layoutParams.rightMargin = AndroidUtilities.dp(15.0f);
                layoutParams.topMargin = AndroidUtilities.dp(15.0f);
            }
            if (getItemCount() % 2 == 0) {
                if (position == getItemCount() - 1 || position == getItemCount() - 2) {
                    layoutParams.bottomMargin = AndroidUtilities.dp(15.0f);
                }
            } else if (position == getItemCount() - 1) {
                layoutParams.bottomMargin = AndroidUtilities.dp(15.0f);
            }
            holder.itemView.setLayoutParams(layoutParams);
            if (AddTopicFragment.this.cacheSelectedHashmap.get(item.ID + "" + item.TypeID) == null) {
                holder.itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (Theme.getCurrentTheme().isLight()) {
                holder.itemView.setBackground(DrawableUtils.createLayerDrawable(AddTopicFragment.this.context.getResources().getColor(R.color.color_F0FCFF), AddTopicFragment.this.context.getResources().getColor(R.color.color_2ECEFD), 0.0f));
            } else {
                holder.itemView.setBackground(DrawableUtils.createLayerDrawable(AndroidUtilities.alphaColor(0.1f, -983809), AddTopicFragment.this.context.getResources().getColor(R.color.color_2ECEFD), 0.0f));
            }
            MryTextView tv_title = (MryTextView) holder.itemView.findViewById(R.attr.tv_title);
            MryTextView tv_subtitle = (MryTextView) holder.itemView.findViewById(R.attr.tv_subtitle);
            MryTextView tv_tag = (MryTextView) holder.itemView.findViewById(R.attr.tv_tag);
            tv_subtitle.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
            tv_tag.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            SpanUtils.with(tv_title).append("#").setForegroundColor(-13709571).append(item.TopicName).setForegroundColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText)).create();
            tv_subtitle.setText(item.Subtitle);
            if (item.Tag == 1) {
                tv_tag.setText(LocaleController.getString("fc_new", R.string.fc_new));
                tv_tag.setBackground(DrawableUtils.getGradientDrawable(new float[]{AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f}, AddTopicFragment.this.context.getResources().getColor(R.color.color_FFFD8A94), AddTopicFragment.this.context.getResources().getColor(R.color.color_FFFD6FCB)));
            } else if (item.Tag == 2) {
                tv_tag.setText(LocaleController.getString("fc_recommend", R.string.fc_recommend));
                tv_tag.setBackground(DrawableUtils.getGradientDrawable(new float[]{AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f}, AddTopicFragment.this.context.getResources().getColor(R.color.color_FF50F7FD), AddTopicFragment.this.context.getResources().getColor(R.color.color_FF2ED2FE)));
            } else {
                tv_tag.setVisibility(8);
            }
        }
    }

    private void getTopics(int pageNo) {
        Observable<BResponse<RespTopicBean>> observable = ApiFactory.getInstance().getApiMomentForum().getFcTopic(this.TopicTypeID, this.TopicName, pageNo * 20, 20);
        RxHelper.getInstance().sendRequest(TAG, observable, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AddTopicFragment$4k-VlVSUqvwwZ4yF5vD2RgNBPkc
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$getTopics$1$AddTopicFragment((BResponse) obj);
            }
        }, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AddTopicFragment$_mMfsFFTgmBT6qwkRHcrabgskgQ
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$getTopics$2$AddTopicFragment((Throwable) obj);
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ void lambda$getTopics$1$AddTopicFragment(BResponse response) throws Exception {
        if (response != null && response.isState()) {
            if (response.Data != 0) {
                List<RespTopicBean.Item> topics = ((RespTopicBean) response.Data).getTopics();
                this.respTopicBeans = topics;
                this.myAdapter.addData((List) topics);
                return;
            }
            this.myAdapter.showEmpty();
        }
    }

    public /* synthetic */ void lambda$getTopics$2$AddTopicFragment(Throwable throwable) throws Exception {
        this.myAdapter.showError(LocaleController.getString("request_fialed", R.string.fc_request_fialed));
    }

    public void setselectedItemCount(HashMap<String, RespTopicBean.Item> cacheSelectedHashmap) {
        this.cacheSelectedHashmap = cacheSelectedHashmap;
        MyAdapter myAdapter = this.myAdapter;
        if (myAdapter != null) {
            myAdapter.notifyDataSetChanged();
        }
    }
}
