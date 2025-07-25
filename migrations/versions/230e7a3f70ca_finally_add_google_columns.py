"""finally add google columns

Revision ID: 230e7a3f70ca
Revises: 9c0a0962b193
Create Date: 2025-07-14 11:24:33.900578

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '230e7a3f70ca'
down_revision = '9c0a0962b193'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable='False')
        batch_op.alter_column('blog_id',
               existing_type=sa.INTEGER(),
               nullable='False')

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('google_id', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('profile_pic', sa.Text(), nullable=True))
        batch_op.create_unique_constraint('uq_user_google_id', ['google_id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')
        batch_op.drop_column('profile_pic')
        batch_op.drop_column('google_id')

    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.alter_column('blog_id',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=True)

    # ### end Alembic commands ###
