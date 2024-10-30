using Microsoft.EntityFrameworkCore;
using Olssen.Slp.Infrastructure;
using Keynius.Backend.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace Olssen.Slp.Repository
{
    /// <summary>
    /// Generic Repository For EF Core
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class GenericRepository<T> : AbstractGenericRepository<T>, IGenericRepository<T> where T : class
    {
        private readonly ApplicationDbContext _context;
        public GenericRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        protected ApplicationDbContext Context => _context;

        public override async ValueTask<T> GetByIdAsync(object key)
            => await _context.FindAsync<T>(new object[] { key });

        public override async ValueTask<T> GetByIdAsync(object[] key)
            => await _context.FindAsync<T>(key);

        public override async Task<T> FirstOrDefaultAsync(Expression<Func<T, bool>> predicate)
            => await _context.Set<T>().FirstOrDefaultAsync(predicate);

        public override async Task<T> GetFirstOrDefaultAsyncWithIncludes(Expression<Func<T, bool>> predicate, params Expression<Func<T, object>>[] includes)
        {
            var query = _context.Set<T>().Where(predicate);

            if (includes != null)
            {
                query = includes.Aggregate(query, (current, include) => current.Include(include));
            }

            return await query.FirstOrDefaultAsync();
        }

        public override IQueryable<T> GetQueryable()
            => _context.Set<T>().AsQueryable<T>();

        public override IQueryable<T> GetQueryableWithIncludes(params Expression<Func<T, object>>[] includes)
        {
            var query = _context.Set<T>().AsQueryable<T>();

            if (includes != null)
            {
                query = includes.Aggregate(query, (current, include) => current.Include(include));
            }

            return query;
        }

        protected override async Task<T> PerformAdd(T entity)
            => (await _context.AddAsync(entity)).Entity;

        protected override async Task PerformAddRange(IEnumerable<T> entities)
            => await _context.AddRangeAsync(entities.ToArray());

        protected override T PerformUpdate(T entity)
            => _context.Update(entity).Entity;

        protected override void PerformDelete(T entity)
        {
            if (entity is ISoftDeletable softDeletable)
                softDeletable.Delete();
            else
                _context.Remove(entity);
        }

        protected override async Task<T> PerformUpsert(object id, T entity)
        {
            var txn = await _context.Database.BeginTransactionAsync();
            try
            {
                var oldEntity = await GetByIdAsync(id);
                if (oldEntity != null)
                {
                    _context.Remove(oldEntity);
                    _context.Attach(entity);
                    _context.Entry(entity).State = EntityState.Modified;
                }
                else
                    await AddAsync(entity);

                await _context.SaveChangesAsync();
                await txn.CommitAsync();
                return entity;
            }
            catch
            {
                await txn.RollbackAsync();
                throw;
            }            
        }

        protected override async Task<T> PerformUpsert(object[] id, T entity)
        {
            var txn = await _context.Database.BeginTransactionAsync();
            try
            {
                var oldEntity = await GetByIdAsync(id);
                if (oldEntity != null)
                {
                    _context.Remove(oldEntity);
                    _context.Attach(entity);
                    _context.Entry(entity).State = EntityState.Modified;
                }
                else
                    await AddAsync(entity);

                await _context.SaveChangesAsync();
                await txn.CommitAsync();
                return entity;
            }
            catch
            {
                await txn.RollbackAsync();
                throw;
            }
        }

        protected override async Task SaveAsync()
            => await _context.SaveChangesAsync();

        public override async Task<TEntity> GetFirst<TEntity>(Expression<Func<TEntity, bool>> predicate)
            => await _context.Set<TEntity>().FirstOrDefaultAsync(predicate);

        public override async Task<bool> AnyAsync(Expression<Func<T, bool>> predicate)
            => await _context.Set<T>().AnyAsync(predicate);
    }
}
