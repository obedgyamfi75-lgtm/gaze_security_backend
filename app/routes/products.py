"""
GAZE Security Platform - Products Routes
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from app import db
from app.models import Product, ProductStatus, Criticality, Asset, User

products_bp = Blueprint('products', __name__)


@products_bp.route('/')
@login_required
def index():
    """List all products"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('perPage', 20, type=int)
        status = request.args.get('status', '')
        criticality = request.args.get('criticality', '')
        search = request.args.get('search', '')
        
        query = Product.query
        
        if status:
            try:
                query = query.filter(Product.status == ProductStatus(status))
            except ValueError:
                pass
        
        if criticality:
            try:
                query = query.filter(Product.criticality == Criticality(criticality))
            except ValueError:
                pass
        
        if search:
            query = query.filter(
                db.or_(
                    Product.name.ilike(f'%{search}%'),
                    Product.short_name.ilike(f'%{search}%'),
                    Product.description.ilike(f'%{search}%')
                )
            )
        
        products = query.order_by(Product.created_at.desc()).paginate(page=page, per_page=per_page)
        
        return jsonify({
            'success': True,
            'data': {
                'items': [p.to_dict() for p in products.items],
                'meta': {
                    'page': page,
                    'perPage': per_page,
                    'totalPages': products.pages,
                    'totalItems': products.total,
                }
            }
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@products_bp.route('/<uuid:product_id>')
@login_required
def get_product(product_id):
    """Get single product"""
    product = Product.query.get_or_404(product_id)
    return jsonify({
        'success': True,
        'data': product.to_dict(include_team=True)
    })


@products_bp.route('/', methods=['POST'])
@login_required
def create_product():
    """Create new product"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    required_fields = ['name', 'shortName']
    for field in required_fields:
        if field not in data:
            return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
    
    try:
        product = Product(
            name=data['name'],
            short_name=data['shortName'],
            description=data.get('description'),
            status=ProductStatus(data.get('status', 'active')),
            criticality=Criticality(data.get('criticality', 'medium')),
            owner_id=current_user.id,
            compliance=data.get('compliance', [])
        )
        
        db.session.add(product)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': product.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@products_bp.route('/<uuid:product_id>', methods=['PUT'])
@login_required
def update_product(product_id):
    """Update product"""
    product = Product.query.get_or_404(product_id)
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    try:
        if 'name' in data:
            product.name = data['name']
        if 'shortName' in data:
            product.short_name = data['shortName']
        if 'description' in data:
            product.description = data['description']
        if 'status' in data:
            product.status = ProductStatus(data['status'])
        if 'criticality' in data:
            product.criticality = Criticality(data['criticality'])
        if 'compliance' in data:
            product.compliance = data['compliance']
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': product.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@products_bp.route('/<uuid:product_id>', methods=['DELETE'])
@login_required
def delete_product(product_id):
    """Delete product"""
    product = Product.query.get_or_404(product_id)
    
    try:
        db.session.delete(product)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@products_bp.route('/<uuid:product_id>/assets')
@login_required
def get_product_assets(product_id):
    """Get assets for a product"""
    product = Product.query.get_or_404(product_id)
    
    return jsonify({
        'success': True,
        'data': [a.to_dict() for a in product.assets]
    })


@products_bp.route('/<uuid:product_id>/findings')
@login_required
def get_product_findings(product_id):
    """Get findings for a product"""
    from app.models import Finding
    
    product = Product.query.get_or_404(product_id)
    
    findings = []
    for asset in product.assets:
        for assessment in asset.assessments:
            findings.extend([f.to_dict() for f in assessment.findings])
    
    return jsonify({
        'success': True,
        'data': findings
    })


@products_bp.route('/<uuid:product_id>/team')
@login_required
def get_product_team(product_id):
    """Get team members for a product"""
    product = Product.query.get_or_404(product_id)
    
    return jsonify({
        'success': True,
        'data': [
            {'id': str(m.id), 'name': m.full_name, 'email': m.email, 'role': m.role.value}
            for m in product.team_members
        ]
    })


@products_bp.route('/<uuid:product_id>/team', methods=['POST'])
@login_required
def add_team_member(product_id):
    """Add team member to product"""
    product = Product.query.get_or_404(product_id)
    data = request.get_json()
    
    if not data or 'userId' not in data:
        return jsonify({'success': False, 'error': 'userId is required'}), 400
    
    user = User.query.get(data['userId'])
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    if user not in product.team_members:
        product.team_members.append(user)
        db.session.commit()
    
    return jsonify({'success': True})


@products_bp.route('/<uuid:product_id>/team/<uuid:user_id>', methods=['DELETE'])
@login_required
def remove_team_member(product_id, user_id):
    """Remove team member from product"""
    product = Product.query.get_or_404(product_id)
    user = User.query.get_or_404(user_id)
    
    if user in product.team_members:
        product.team_members.remove(user)
        db.session.commit()
    
    return jsonify({'success': True})