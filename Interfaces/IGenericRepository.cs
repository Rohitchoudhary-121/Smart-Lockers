using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace Olssen.Slp.Repository
{
    public interface IGenericRepository<T> : IGenericRepository where T : class
    {
        /// <summary>
        /// Add an entity Asynchnously
        /// </summary>
        /// <param name="entity">Entity To Add</param>
        /// <returns>Returns Entity Added</returns>
        Task<T> AddAsync(T entity);

        /// <summary>
        /// Add a range of entities Asynchnously
        /// </summary>
        /// <param name="entities">Entities To Add</param>
        /// <returns>Returns Entities Added</returns>
        Task<IEnumerable<T>> AddRangeAsync(IEnumerable<T> entities);

        /// <summary>
        /// Delete an entity Asynchnously
        /// </summary>
        /// <param name="entity">Entity to Delete</param>
        Task DeleteAsync(T entity);

        /// <summary>
        /// Delete an entity by id/key Asynchnously
        /// </summary>
        /// <param name="id">Id/key of the entity to delete</param>
        Task DeleteByIdAsync(object id);


        /// <summary>
        /// Delete an entity by id/key Asynchnously (For Compound)
        /// </summary>
        /// <param name="id">Id/key of the entity to delete</param>
        Task DeleteByIdAsync(object[] id);

        Task DeleteRangeAsync(IList<T> entities);

        /// <summary>
        /// Get First or Default Entity based on Predicate Asynchnously
        /// </summary>
        /// <param name="predicate">Predicate</param>
        /// <returns></returns>
        Task<T> FirstOrDefaultAsync(Expression<Func<T, bool>> predicate);

        Task<T> GetFirstOrDefaultAsyncWithIncludes(Expression<Func<T, bool>> predicate, params Expression<Func<T, object>>[] includes);

        /// <summary>
        /// Get Entity by Id/Key Asynchronously
        /// </summary>
        /// <param name="key">Id/Key</param>
        /// <returns>Entity/null if not found</returns>
        ValueTask<T> GetByIdAsync(object key);

        /// <summary>
        /// Get Entity by Id/Key Asynchronously (For Composite Keys)
        /// </summary>
        /// <param name="key">Composite Id/Key</param>
        /// <returns>Entity/null if not found</returns>
        ValueTask<T> GetByIdAsync(object[] key);

        /// <summary>
        /// Get Repository as IQueryable
        /// </summary>
        /// <returns></returns>
        IQueryable<T> GetQueryable();

        /// <summary>
        /// Get Repository as IQueryable with includes
        /// </summary>
        /// <returns></returns>
        IQueryable<T> GetQueryableWithIncludes(params Expression<Func<T, object>>[] includes);


        /// <summary>
        /// Updates Entity Asynchronously
        /// </summary>
        /// <param name="entity">Entity to Update</param>
        /// <returns>Updated Entity</returns>
        Task<T> UpdateAsync(T entity);

        /// <summary>
        /// Updates a collection of entities asychronously
        /// </summary>
        /// <param name="entities">entities to be updated.</param>
        /// <returns>Updated entities</returns>
        Task<List<T>> UpdateRangeAsync(IEnumerable<T> entities);

        /// <summary>
        /// Upserts (Delete & Insert Entity Asynchronously)
        /// </summary>
        /// <param name="id">Id of the entity</param>
        /// <param name="entity">entity to upsert</param>
        /// <returns>Updated Entity</returns>
        Task<T> UpsertAsync(object id, T entity);

        /// <summary>
        /// Upserts (Delete & Insert Entity Asynchronously) For Compound Keys
        /// </summary>
        /// <param name="id">Compound Key/Id of the entity</param>
        /// <param name="entity">entity to upsert</param>
        /// <returns>Updated Entity</returns>
        Task<T> UpsertAsync(object[] id, T entity);        

        /// <summary>
        /// Get Any Entity exists based on Predicate Asynchronously
        /// </summary>
        /// <param name="predicate">Predicate</param>
        /// <returns></returns>
        Task<bool> AnyAsync(Expression<Func<T, bool>> predicate);



    }

    public interface IGenericRepository
    {
        /// <summary>
        /// Get an Entity of specified type based on predicate
        /// </summary>
        /// <typeparam name="TEntity">Type of Entity</typeparam>
        /// <param name="predicate">Predicate</param>
        /// <returns>Entity</returns>
        Task<TEntity> GetFirst<TEntity>(Expression<Func<TEntity, bool>> predicate) where TEntity : class;
    }
}