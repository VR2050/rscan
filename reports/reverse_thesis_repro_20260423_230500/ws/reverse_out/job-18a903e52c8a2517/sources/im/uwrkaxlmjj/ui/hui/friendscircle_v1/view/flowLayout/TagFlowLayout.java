package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import com.king.zxing.util.LogUtils;
import im.uwrkaxlmjj.messenger.R;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagAdapter;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/* JADX INFO: loaded from: classes5.dex */
public class TagFlowLayout extends FlowLayout implements TagAdapter.OnDataChangedListener {
    private static final String KEY_CHOOSE_POS = "key_choose_pos";
    private static final String KEY_DEFAULT = "key_default";
    private static final String TAG = "TagFlowLayout";
    private OnSelectListener mOnSelectListener;
    private OnTagClickListener mOnTagClickListener;
    private int mSelectedMax;
    private Set<Integer> mSelectedView;
    private TagAdapter mTagAdapter;

    public interface OnSelectListener {
        void onSelected(Set<Integer> set);
    }

    public interface OnTagClickListener {
        boolean onTagClick(View view, int i, FlowLayout flowLayout);
    }

    public TagFlowLayout(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        this.mSelectedMax = -1;
        this.mSelectedView = new HashSet();
        TypedArray ta = context.obtainStyledAttributes(attrs, R.styleable.TagFlowLayout);
        this.mSelectedMax = ta.getInt(0, -1);
        ta.recycle();
    }

    public TagFlowLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public TagFlowLayout(Context context) {
        this(context, null);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.FlowLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int cCount = getChildCount();
        for (int i = 0; i < cCount; i++) {
            TagView tagView = (TagView) getChildAt(i);
            if (tagView.getVisibility() != 8 && tagView.getTagView().getVisibility() == 8) {
                tagView.setVisibility(8);
            }
        }
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
    }

    public void setOnSelectListener(OnSelectListener onSelectListener) {
        this.mOnSelectListener = onSelectListener;
    }

    public void setOnTagClickListener(OnTagClickListener onTagClickListener) {
        this.mOnTagClickListener = onTagClickListener;
    }

    public void setAdapter(TagAdapter adapter) {
        this.mTagAdapter = adapter;
        adapter.setOnDataChangedListener(this);
        this.mSelectedView.clear();
        changeAdapter();
    }

    private void changeAdapter() {
        removeAllViews();
        TagAdapter adapter = this.mTagAdapter;
        HashSet<Integer> preCheckedList = this.mTagAdapter.getPreCheckedList();
        for (int i = 0; i < adapter.getCount(); i++) {
            View tagView = adapter.getView(this, i, adapter.getItem(i));
            final TagView tagViewContainer = new TagView(getContext());
            tagView.setDuplicateParentStateEnabled(true);
            if (tagView.getLayoutParams() != null) {
                tagViewContainer.setLayoutParams(tagView.getLayoutParams());
            } else {
                ViewGroup.MarginLayoutParams lp = new ViewGroup.MarginLayoutParams(-2, -2);
                lp.setMargins(dip2px(getContext(), 5.0f), dip2px(getContext(), 5.0f), dip2px(getContext(), 5.0f), dip2px(getContext(), 5.0f));
                tagViewContainer.setLayoutParams(lp);
            }
            tagView.setLayoutParams(new ViewGroup.LayoutParams(-1, -1));
            tagViewContainer.addView(tagView);
            addView(tagViewContainer);
            if (preCheckedList.contains(Integer.valueOf(i))) {
                setChildChecked(i, tagViewContainer);
            }
            if (this.mTagAdapter.setSelected(i, adapter.getItem(i))) {
                setChildChecked(i, tagViewContainer);
            }
            tagView.setClickable(false);
            final int position = i;
            tagViewContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagFlowLayout.1
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    TagFlowLayout.this.doSelect(tagViewContainer, position);
                    if (TagFlowLayout.this.mOnTagClickListener != null) {
                        TagFlowLayout.this.mOnTagClickListener.onTagClick(tagViewContainer, position, TagFlowLayout.this);
                    }
                }
            });
        }
        this.mSelectedView.addAll(preCheckedList);
    }

    public void setMaxSelectCount(int count) {
        if (this.mSelectedView.size() > count) {
            Log.w(TAG, "you has already select more than " + count + " views , so it will be clear .");
            this.mSelectedView.clear();
        }
        this.mSelectedMax = count;
    }

    public Set<Integer> getSelectedList() {
        return new HashSet(this.mSelectedView);
    }

    private void setChildChecked(int position, TagView view) {
        view.setChecked(true);
        this.mTagAdapter.onSelected(position, view.getTagView());
    }

    private void setChildUnChecked(int position, TagView view) {
        view.setChecked(false);
        this.mTagAdapter.unSelected(position, view.getTagView());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void doSelect(TagView child, int position) {
        if (!child.isChecked()) {
            if (this.mSelectedMax == 1 && this.mSelectedView.size() == 1) {
                Iterator<Integer> iterator = this.mSelectedView.iterator();
                Integer preIndex = iterator.next();
                TagView pre = (TagView) getChildAt(preIndex.intValue());
                setChildUnChecked(preIndex.intValue(), pre);
                setChildChecked(position, child);
                this.mSelectedView.remove(preIndex);
                this.mSelectedView.add(Integer.valueOf(position));
            } else {
                if (this.mSelectedMax > 0 && this.mSelectedView.size() >= this.mSelectedMax) {
                    return;
                }
                setChildChecked(position, child);
                this.mSelectedView.add(Integer.valueOf(position));
            }
        } else {
            setChildUnChecked(position, child);
            this.mSelectedView.remove(Integer.valueOf(position));
        }
        OnSelectListener onSelectListener = this.mOnSelectListener;
        if (onSelectListener != null) {
            onSelectListener.onSelected(new HashSet(this.mSelectedView));
        }
    }

    public TagAdapter getAdapter() {
        return this.mTagAdapter;
    }

    @Override // android.view.View
    protected Parcelable onSaveInstanceState() {
        Bundle bundle = new Bundle();
        bundle.putParcelable(KEY_DEFAULT, super.onSaveInstanceState());
        String selectPos = "";
        if (this.mSelectedView.size() > 0) {
            Iterator<Integer> it = this.mSelectedView.iterator();
            while (it.hasNext()) {
                int key = it.next().intValue();
                selectPos = selectPos + key + LogUtils.VERTICAL;
            }
            selectPos = selectPos.substring(0, selectPos.length() - 1);
        }
        bundle.putString(KEY_CHOOSE_POS, selectPos);
        return bundle;
    }

    @Override // android.view.View
    protected void onRestoreInstanceState(Parcelable state) {
        if (state instanceof Bundle) {
            Bundle bundle = (Bundle) state;
            String mSelectPos = bundle.getString(KEY_CHOOSE_POS);
            if (!TextUtils.isEmpty(mSelectPos)) {
                String[] split = mSelectPos.split("\\|");
                for (String pos : split) {
                    int index = Integer.parseInt(pos);
                    this.mSelectedView.add(Integer.valueOf(index));
                    TagView tagView = (TagView) getChildAt(index);
                    if (tagView != null) {
                        setChildChecked(index, tagView);
                    }
                }
            }
            super.onRestoreInstanceState(bundle.getParcelable(KEY_DEFAULT));
            return;
        }
        super.onRestoreInstanceState(state);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.flowLayout.TagAdapter.OnDataChangedListener
    public void onChanged() {
        this.mSelectedView.clear();
        changeAdapter();
    }

    public static int dip2px(Context context, float dpValue) {
        float scale = context.getResources().getDisplayMetrics().density;
        return (int) ((dpValue * scale) + 0.5f);
    }
}
