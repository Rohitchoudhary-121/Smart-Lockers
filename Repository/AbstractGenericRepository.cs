using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace Olssen.Slp.Repository
{
    /// <summary>
    /// Base Class for All Generic Repositories(EF, MongoDb, etc)
    /// </summary>
    public abstract class AbstractGenericRepository<T> : IGenericRepository<T> where T : class
    {

        public abstract ValueTask<T> GetByIdAsync(object key);

        public abstract ValueTask<T> GetByIdAsync(object[] key);

        public abstract Task<T> FirstOrDefaultAsync(Expression<Func<T, bool>> predicate);
        public abstract Task<T> GetFirstOrDefaultAsyncWithIncludes(Expression<Func<T, bool>> predicate, params Expression<Func<T, object>>[] includes);

        public abstract Task<bool> AnyAsync(Expression<Func<T, bool>> predicate);

        public abstract IQueryable<T> GetQueryable();
        public abstract IQueryable<T> GetQueryableWithIncludes(params Expression<Func<T, object>>[] includes);

        public async Task<T> AddAsync(T entity)
        {
            await PerformAdd(entity);
            await SaveAsync();
            return entity;
        }

        public async Task<IEnumerable<T>> AddRangeAsync(IEnumerable<T> entities)
        {
            await PerformAddRange(entities);
            await SaveAsync();
            return entities;
        }

        protected abstract Task<T> PerformAdd(T entity);

        protected abstract Task PerformAddRange(IEnumerable<T> entities);

        protected virtual Task SaveAsync()
            => Task.CompletedTask;

        public async Task<T> UpdateAsync(T entity)
        {
            var updated = PerformUpdate(entity);
            await SaveAsync();
            return updated;
        }

        public async Task<List<T>> UpdateRangeAsync(IEnumerable<T> entities)
        {
            var entityList = entities.ToList();
            var updatedList = new List<T>();
            for (int i = 0; i < entityList.Count; i++)
            {
                var entity = entityList[i];
                var updated = PerformUpdate(entity);
                updatedList.Add(updated);
            }

            await SaveAsync();
            return updatedList;
        }

        protected abstract T PerformUpdate(T entity);
        protected abstract Task<T> PerformUpsert(object id, T entity);
        protected abstract Task<T> PerformUpsert(object[] id, T entity);

        public async Task DeleteAsync(T entity)
        {
            PerformDelete(entity);
            await SaveAsync();
        }

        /// <summary>
        /// Deletes a bunch of objects at one go.
        /// </summary>
        /// <param name="entities">collection of entities to be deleted.</param>
        public async Task DeleteRangeAsync(IList<T> entities)
        {
            for (int i = 0; i < entities.Count; i++)
            {
                var entity = entities[i];
                PerformDelete(entity); 
            }
            await SaveAsync();
        }

        public abstract Task<TEntity> GetFirst<TEntity>(Expression<Func<TEntity, bool>> predicate) where TEntity : class;

        protected abstract void PerformDelete(T entity);

        public async Task DeleteByIdAsync(object id)
        {
            var entity = await GetByIdAsync(id);
            if (entity != null)
                await DeleteAsync(entity);

        }

        public async Task DeleteByIdAsync(object[] id)
        {
            var entity = await GetByIdAsync(id);
            if (entity != null)
                await DeleteAsync(entity);

        }

        public Task<T> UpsertAsync(object id, T entity)
            => PerformUpsert(id, entity);

        public Task<T> UpsertAsync(object[] id, T entity)
           => PerformUpsert(id, entity);
    }
}
