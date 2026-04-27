package im.uwrkaxlmjj.ui.hui.adapter.grouping;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.view.View;
import android.widget.ImageView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.expand.models.ExpandableGroup;
import im.uwrkaxlmjj.ui.expand.viewholders.GroupViewHolder;
import im.uwrkaxlmjj.ui.hcells.MryDividerCell;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class GenreViewHolder extends GroupViewHolder {
    private MryDividerCell divider;
    private int flatPosition;
    private ExpandableGroup genre;
    private List<? extends ExpandableGroup> groups;
    private ImageView ivArrow;
    private MryTextView tvGenreName;
    private MryTextView tvGenreOnlineNumber;

    public GenreViewHolder(View itemView) {
        super(itemView);
        this.tvGenreName = (MryTextView) itemView.findViewById(R.attr.list_item_genre_name);
        this.tvGenreOnlineNumber = (MryTextView) itemView.findViewById(R.attr.list_item_genre_online_number);
        this.ivArrow = (ImageView) itemView.findViewById(R.attr.list_item_genre_arrow);
        this.divider = (MryDividerCell) itemView.findViewById(R.attr.divider);
    }

    public void setGenreData(ExpandableGroup genre, int flatPosition, List<? extends ExpandableGroup> groups) {
        this.genre = genre;
        this.flatPosition = flatPosition;
        this.groups = groups;
        initData();
    }

    private void initData() {
        ExpandableGroup expandableGroup = this.genre;
        if (expandableGroup instanceof Genre) {
            this.tvGenreName.setText(expandableGroup.getTitle());
            this.tvGenreOnlineNumber.setText(((Genre) this.genre).getOnlineCount() + "/" + this.genre.getItemCount());
        }
        if (this.groups.size() == 1) {
            this.itemView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            this.divider.setVisibility(8);
        } else {
            if (this.flatPosition == 0) {
                this.itemView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                return;
            }
            ExpandableGroup expandableGroup2 = this.genre;
            List<? extends ExpandableGroup> list = this.groups;
            if (expandableGroup2 == list.get(list.size() - 1)) {
                this.divider.setVisibility(8);
                this.itemView.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.expand.viewholders.GroupViewHolder
    public void expand() {
        animateExpand();
    }

    @Override // im.uwrkaxlmjj.ui.expand.viewholders.GroupViewHolder
    public void collapse() {
        animateCollapse();
    }

    private void animateExpand() {
        final ObjectAnimator animator = ObjectAnimator.ofFloat(this.ivArrow, "rotation", 0.0f, 90.0f);
        animator.setDuration(300L);
        animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.adapter.grouping.GenreViewHolder.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animation) {
                if (GenreViewHolder.this.groups.size() != 1) {
                    if (GenreViewHolder.this.genre != GenreViewHolder.this.groups.get(GenreViewHolder.this.groups.size() - 1)) {
                        GenreViewHolder.this.divider.setVisibility(8);
                    } else {
                        GenreViewHolder.this.itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    }
                } else {
                    GenreViewHolder.this.itemView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                }
                animator.removeListener(this);
            }
        });
        animator.start();
    }

    private void animateCollapse() {
        final ObjectAnimator animator = ObjectAnimator.ofFloat(this.ivArrow, "rotation", 90.0f, 0.0f);
        animator.setDuration(300L);
        animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.adapter.grouping.GenreViewHolder.2
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (GenreViewHolder.this.groups.size() != 1) {
                    if (GenreViewHolder.this.genre != GenreViewHolder.this.groups.get(GenreViewHolder.this.groups.size() - 1)) {
                        GenreViewHolder.this.divider.setVisibility(0);
                    } else {
                        GenreViewHolder.this.itemView.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    }
                } else {
                    GenreViewHolder.this.itemView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                }
                animator.removeListener(this);
            }
        });
        animator.start();
    }
}
